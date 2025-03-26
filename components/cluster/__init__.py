import asyncio
import base64
import json
import os
import random
import re
import socket
import sys
import zlib

from config import defaults
from contextlib import closing, suppress
from components.cluster.exceptions import (
    IncompleteClusterResponses,
    DistLockCancelled,
    UnknownPeer,
    ZombiePeer,
)
from components.cluster.cli import cli_processor
from components.models.cluster import (
    CritErrors,
    Role,
    FilePath,
    validate_call,
    ConnectionStatus,
)
from components.cluster.leader import elect_leader
from components.cluster.peers import Peers
from components.cluster.monitor import Monitor
from components.cluster.ssl import get_ssl_context
from components.logs import logger
from components.database import *
from components.utils.cryptography import dict_digest_sha1
from components.utils.datetimes import ntime_utc_now
from components.utils import ensure_list, is_path_within_cwd, chunk_string


class Cluster:
    def __init__(self, peers, port):
        self.locks = dict()
        self.port = port
        self.receiving = asyncio.Condition()
        self.tickets = dict()
        self._partial_tickets = dict()
        self.monitor = Monitor(self)
        self.server_limit = 104857600  # 100 MiB
        self.peers = Peers(peers)
        self.sending = asyncio.Lock()
        self._session_patched_tables = dict()

    async def read_command(self, reader: asyncio.StreamReader) -> tuple[str, str, dict]:
        bytes_to_read = int.from_bytes(await reader.readexactly(4), "big")
        input_bytes = await reader.readexactly(bytes_to_read)

        input_decoded = input_bytes.strip().decode("utf-8")
        data, _, meta = input_decoded.partition(" :META ")
        ticket, _, cmd = data.partition(" ")

        patterns = [
            r"NAME (?P<name>\S+)",
            r"SWARM (?P<swarm>\S+)",
            r"STARTED (?P<started>\S+)",
            r"LEADER (?P<leader>\S+)",
        ]

        match = re.search(" ".join(patterns), meta)
        meta_dict = match.groupdict()
        name = meta_dict["name"]

        if not name in self.peers.remotes:
            raise UnknownPeer(name)

        self.peers.remotes[name].leader = meta_dict["leader"]
        self.peers.remotes[name].started = float(meta_dict["started"])
        self.peers.remotes[name].swarm = meta_dict["swarm"]

        msg = cmd[:150] + (cmd[150:] and "...")
        logger.debug(f"[← Receiving from {name}][{ticket}] - {msg}")

        return ticket, cmd, meta_dict

    async def incoming_handler(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        monitor_init = False
        raddr, *_ = writer.get_extra_info("peername")
        socket, *_ = writer.get_extra_info("socket").getsockname()

        if socket and raddr in defaults.CLUSTER_CLI_BINDINGS:
            return await cli_processor((reader, writer))

        if raddr not in self.peers.remote_ips():
            raise UnknownPeer(raddr)

        while True:
            try:
                ticket, cmd, peer_meta = await self.read_command(reader)
                if not monitor_init:
                    self.peers.remotes[peer_meta["name"]].streams._in = (
                        reader,
                        writer,
                    )
                    await self.monitor.start_peer_monitoring(peer_meta["name"])
                    monitor_init = True
            except (asyncio.exceptions.IncompleteReadError, ConnectionResetError):
                break
            except TimeoutError as e:
                if str(e) == "SSL shutdown timed out":
                    break
                raise
            except ZombiePeer:
                await self.send_command(
                    CritErrors.ZOMBIE.response, peer_meta["name"], ticket=ticket
                )
                break
            try:
                if not self.peers.local.leader and not any(
                    map(
                        lambda s: cmd.startswith(s),
                        ["ACK", "STATUS", "FULLTABLE", "INIT"],
                    )
                ):
                    await self.send_command(
                        CritErrors.NOT_READY.response, peer_meta["name"], ticket=ticket
                    )

                elif cmd.startswith("PATCHTABLE") or cmd.startswith("FULLTABLE"):
                    _, _, payload = cmd.partition(" ")
                    table_w_hash, table_payload = payload.split(" ")
                    table, table_digest = table_w_hash.split("@")
                    db_params = evaluate_db_params(ticket)

                    async with TinyDB(**db_params) as db:
                        if not table in db.tables():
                            await self.send_command(
                                CritErrors.NO_SUCH_TABLE.response,
                                peer_meta["name"],
                                ticket=ticket,
                            )
                        else:
                            if not ticket in self._session_patched_tables:
                                self._session_patched_tables[ticket] = set()

                            self._session_patched_tables[ticket].add(table)

                            try:
                                if cmd.startswith("PATCHTABLE"):
                                    table_data = {
                                        doc.doc_id: doc for doc in db.table(table).all()
                                    }
                                    errors = []
                                    local_table_digest = dict_digest_sha1(table_data)
                                    if local_table_digest != table_digest:
                                        await self.send_command(
                                            CritErrors.TABLE_HASH_MISMATCH.response,
                                            peer_meta["name"],
                                            ticket=ticket,
                                        )
                                        continue

                                    diff = json.loads(base64.b64decode(table_payload))

                                    for doc_id, docs in diff["changed"].items():
                                        a, b = docs
                                        c = db.table(table).get(doc_id=doc_id)
                                        if c != a:
                                            await self.send_command(
                                                CritErrors.DOC_MISMATCH.response,
                                                peer_meta["name"],
                                                ticket=ticket,
                                            )
                                            break
                                        db.table(table).upsert(
                                            Document(b, doc_id=doc_id)
                                        )
                                    else:  # if no break occured, continue
                                        for doc_id, doc in diff["added"].items():
                                            db.table(table).insert(
                                                Document(doc, doc_id=doc_id)
                                            )
                                        db.table(table).remove(
                                            Query().id.one_of(
                                                [
                                                    doc["id"]
                                                    for doc in diff["removed"].values()
                                                ]
                                            )
                                        )

                                elif cmd.startswith("FULLTABLE"):
                                    insert_data = json.loads(
                                        base64.b64decode(table_payload)
                                    )
                                    db.table(table).truncate()
                                    for doc_id, doc in insert_data.items():
                                        db.table(table).insert(
                                            Document(doc, doc_id=doc_id)
                                        )

                                await self.send_command(
                                    "ACK", peer_meta["name"], ticket=ticket
                                )

                            except Exception as e:
                                await self.send_command(
                                    CritErrors.CANNOT_APPLY.response,
                                    peer_meta["name"],
                                    ticket=ticket,
                                )
                                continue

                elif cmd == "COMMIT":
                    if not ticket in self._session_patched_tables:
                        await self.send_command(
                            CritErrors.NOTHING_TO_COMMIT.response,
                            peer_meta["name"],
                            ticket=ticket,
                        )
                        continue

                    commit_tables = self._session_patched_tables[ticket]
                    del self._session_patched_tables[ticket]
                    await dbcommit(commit_tables, ticket)
                    await self.send_command("ACK", peer_meta["name"], ticket=ticket)

                elif cmd == "STATUS" or cmd == "INIT":
                    await self.send_command("ACK", peer_meta["name"], ticket=ticket)

                elif cmd == "BYE":
                    self.peers.remotes[peer_meta["name"]] = self.peers.remotes[
                        peer_meta["name"]
                    ].reset()

                elif cmd.startswith("FILEGET"):
                    _, _, payload = cmd.partition(" ")
                    start, end, file = payload.split(" ")

                    if not is_path_within_cwd(file) or not os.path.exists(file):
                        await self.send_command(
                            CritErrors.INVALID_FILE_PATH.response,
                            peer_meta["name"],
                            ticket=ticket,
                        )
                        continue

                    if os.stat(file).st_size < int(start):
                        await self.send_command(
                            CritErrors.START_BEHIND_FILE_END.response,
                            peer_meta["name"],
                            ticket=ticket,
                        )
                        continue

                    with open(file, "rb") as f:
                        f.seek(int(start))
                        compressed_data = zlib.compress(f.read(int(end)))
                        compressed_data_encoded = base64.b64encode(
                            compressed_data
                        ).decode("utf-8")

                    chunks = chunk_string(f"{file} {compressed_data_encoded}")
                    for idx, c in enumerate(chunks, 1):
                        await self.send_command(
                            f"PACK CHUNKED {idx} {len(chunks)} {c}",
                            peer_meta["name"],
                            ticket=ticket,
                        )

                elif cmd.startswith("UNLOCK"):
                    _, _, tables_str = cmd.partition(" ")
                    tables = tables_str.split(",")

                    for t in tables:
                        with suppress(RuntimeError):
                            self.locks[t]["lock"].release()
                        self.locks[t]["ticket"] = None

                    await self.send_command("ACK", peer_meta["name"], ticket=ticket)

                elif cmd.startswith("LOCK"):
                    _, _, tables_str = cmd.partition(" ")
                    tables = tables_str.split(",")

                    if peer_meta["swarm"] != self.peers.local.swarm:
                        await self.send_command(
                            CritErrors.PEERS_MISMATCH.response,
                            peer_meta["name"],
                            ticket=ticket,
                        )
                        continue

                    try:
                        for t in tables:
                            if t not in self.locks:
                                self.locks[t] = {
                                    "lock": asyncio.Lock(),
                                    "ticket": None,
                                }
                            await asyncio.wait_for(
                                self.locks[t]["lock"].acquire(),
                                0.3 + random.uniform(0.1, 0.5),
                            )
                            self.locks[t]["ticket"] = ticket

                    except TimeoutError:
                        await self.send_command(
                            "ACK BUSY", peer_meta["name"], ticket=ticket
                        )
                    else:
                        await self.send_command("ACK", peer_meta["name"], ticket=ticket)

                elif cmd.startswith("PACK"):
                    if not ticket in self._partial_tickets:
                        self._partial_tickets[ticket] = []

                    _, _, payload = cmd.partition(" ")
                    _, idx, total, partial_data = payload.split(" ", 3)

                    self._partial_tickets[ticket].append(partial_data)
                    if idx == total:
                        self.tickets[ticket].add(
                            (peer_meta["name"], "".join(self._partial_tickets[ticket]))
                        )

                elif cmd.startswith("ACK"):
                    _, _, payload = cmd.partition(" ")
                    if ticket in self.tickets:
                        self.tickets[ticket].add((peer_meta["name"], payload))

                async with self.receiving:
                    self.receiving.notify_all()

            except ConnectionResetError:
                break

    async def send_command(self, cmd, peers, ticket: str | None = None):
        if not ticket:
            ticket = str(ntime_utc_now())

        if peers == "*":
            peers = self.peers.remotes.keys()
        else:
            peers = ensure_list(peers)

        if ticket not in self.tickets:
            self.tickets[ticket] = set()

        successful_receivers = []

        for name in peers:
            async with self.peers.remotes[name].sending_lock:
                con, status = await self.peers.remotes[name].connect()
                if con:
                    reader, writer = con
                    buffer_data = [
                        ticket,
                        cmd,
                        ":META",
                        f"NAME {self.peers.local.name}",
                        "SWARM {swarm}".format(
                            swarm=self.peers.local.swarm or "?CONFUSED"
                        ),
                        f"STARTED {self.peers.local.started}",
                        "LEADER {leader}".format(
                            leader=self.peers.local.leader or "?CONFUSED"
                        ),
                    ]
                    buffer_bytes = " ".join(buffer_data).encode("utf-8")
                    writer.write(len(buffer_bytes).to_bytes(4, "big"))
                    writer.write(buffer_bytes)
                    await writer.drain()

                    msg = cmd[:150] + (cmd[150:] and "...")
                    logger.debug(f"[→ Sending to {name}][{ticket}] - {msg}")

                    successful_receivers.append(name)
                else:
                    logger.warning(f"Cannot send to peer {name} - {status}")

        return ticket, successful_receivers

    async def release(self, tables: list = ["main"]) -> str:
        errors = []
        CTX_TICKET.reset(self._ctx_ticket)

        if self.peers.local.role == Role.FOLLOWER:
            try:
                ticket, receivers = await self.send_command(
                    f"UNLOCK {','.join(tables)}",
                    self.peers.local.leader,
                )
                async with self.receiving:
                    ret, responses = await self.await_receivers(
                        ticket, receivers, raise_err=True
                    )
            except IncompleteClusterResponses:
                errors.append("leader_not_reachable")

        for t in tables:
            with suppress(RuntimeError):
                self.locks[t]["lock"].release()
            self.locks[t]["ticket"] = None

        if "leader_not_reachable" in errors:
            ticket, receivers = await self.send_command("STATUS", "*")
            async with self.receiving:
                await self.await_receivers(ticket, receivers, raise_err=False)
            raise DistLockCancelled("Master not reachable, trying a re-election")

    async def acquire_lock(self, tables: list = ["main"]) -> str:
        try:
            ticket = str(ntime_utc_now())
            for t in tables:
                if t not in self.locks:
                    self.locks[t] = {
                        "lock": asyncio.Lock(),
                        "ticket": None,
                    }

                await asyncio.wait_for(self.locks[t]["lock"].acquire(), 20.0)
                self.locks[t]["ticket"] = ticket

        except TimeoutError:
            raise DistLockCancelled("Unable to acquire local lock")

        errors = []
        if self.peers.local.role == Role.FOLLOWER:
            try:
                if not self.peers.local.leader:
                    raise IncompleteClusterResponses

                ticket, receivers = await self.send_command(
                    f"LOCK {','.join(tables)}", self.peers.local.leader
                )

                async with self.receiving:
                    result, responses = await self.await_receivers(
                        ticket, receivers, raise_err=False
                    )

                if "BUSY" in responses:
                    errors.append("leader_busy")
                elif not result:
                    if CritErrors.PEERS_MISMATCH in responses:
                        errors.append("lock_rejected")
                    else:
                        errors.append("leader_not_reachable")

            except asyncio.CancelledError:
                errors.append("lock_cancelled")

        if "leader_busy" in errors:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()
            return await self.acquire_lock(tables)

        if "lock_rejected" in errors:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()
            ticket, receivers = await self.send_command("STATUS", "*")
            async with self.receiving:
                await self.await_receivers(ticket, receivers, raise_err=False)
            raise DistLockCancelled("Master rejected LOCK due to inconsistency")

        if "lock_cancelled" in errors:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()
            raise DistLockCancelled("Lock was cancelled")

        if "leader_not_reachable" in errors:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()
            ticket, receivers = await self.send_command("STATUS", "*")
            async with self.receiving:
                await self.await_receivers(ticket, receivers, raise_err=False)
            raise DistLockCancelled("Master not reachable, trying a re-election")

        self._ctx_ticket = CTX_TICKET.set(ticket)

    @validate_call
    async def request_files(
        self,
        files: FilePath | list[FilePath],
        peers: str | list,
        start: int = 0,
        end: int = -1,
    ):
        assert self.locks["files"]["lock"].locked()
        for file in ensure_list(files):
            try:
                if not is_path_within_cwd(file):
                    logger.error(f"File not within cwd: {file}")
                    continue

                for peer in ensure_list(peers):
                    peer_start = start
                    peer_end = end
                    assert peer in self.peers.remotes
                    if peer_start == -1:
                        if os.path.exists(f"peer_files/{peer}/{file}"):
                            peer_start = os.stat(f"peer_files/{peer}/{file}").st_size
                        else:
                            peer_start = 0

                    ticket, receivers = await self.send_command(
                        f"FILEGET {peer_start} {peer_end} {file}", peer
                    )
                    async with self.receiving:
                        _, response = await self.await_receivers(
                            ticket, receivers, raise_err=True
                        )

                    for r in response:
                        r_file, r_data = r.split(" ")
                        assert FilePath(r_file) == file
                        file_dest = f"peer_files/{peer}/{file}"
                        os.makedirs(os.path.dirname(file_dest), exist_ok=True)
                        payload = zlib.decompress(base64.b64decode(r_data))
                        if os.path.exists(file_dest):
                            mode = "r+b"
                        else:
                            mode = "w+b"
                        with open(file_dest, mode) as f:
                            f.seek(peer_start)
                            f.write(payload)

            except IncompleteClusterResponses:
                logger.error(f"Sending command to peers '{peers}' failed")
                raise
            except Exception as e:
                logger.error(f"Unhandled error: {e}")
                raise

    async def run(self, shutdown_trigger) -> None:
        server = await asyncio.start_server(
            self.incoming_handler,
            self.peers.local._all_bindings_as_str,
            self.port,
            ssl=get_ssl_context("server"),
            limit=self.server_limit,
        )
        self._shutdown = shutdown_trigger

        logger.info(
            f"Listening on {self.port} on address {' and '.join(self.peers.local._all_bindings_as_str)}..."
        )

        async with server:
            for name in self.peers.remotes:
                ip, status = self.peers.remotes[name]._eval_ip()
                if ip:
                    con, status = await self.peers.remotes[name].connect(ip)
                    if con:
                        ticket, receivers = await self.send_command("INIT", name)
                        async with self.receiving:
                            ret, responses = await self.await_receivers(
                                ticket, receivers, raise_err=False
                            )
                        if CritErrors.ZOMBIE in responses:
                            logger.critical(
                                f"Peer {name} has not yet disconnected a previous session: {status}"
                            )
                            shutdown_trigger.set()
                            break
                    else:
                        logger.debug(f"Not sending INIT to peer {name}: {status}")
                else:
                    logger.debug(f"Not sending INIT to peer {name}: {status}")

            t = asyncio.create_task(self.monitor._ticket_worker(), name="tickets")
            self.monitor.tasks.add(t)
            t.add_done_callback(self.monitor.tasks.discard)

            try:
                await shutdown_trigger.wait()
            except asyncio.CancelledError:
                if self.peers.get_established():
                    await self.send_command("BYE", "*")

            [t.cancel() for t in self.monitor.tasks]

    async def await_receivers(
        self,
        ticket,
        receivers,
        raise_err: bool,
        timeout: float = defaults.CLUSTER_PEERS_TIMEOUT * len(defaults.CLUSTER_PEERS),
    ):
        errors = []
        missing_receivers = []

        assert self.receiving.locked()

        if timeout >= defaults.CLUSTER_PEERS_TIMEOUT * len(defaults.CLUSTER_PEERS) + 10:
            raise ValueError("Timeout is too high")

        try:
            while not all(
                r in [peer for peer, _ in self.tickets[ticket]] for r in receivers
            ):
                await asyncio.wait_for(self.receiving.wait(), timeout)
        except TimeoutError:
            missing_receivers = [
                r
                for r in receivers
                if r not in [peer for peer, _ in self.tickets[ticket]]
            ]
            errors.append(
                f"Timeout waiting for receviers: {', '.join(missing_receivers)}"
            )

        finally:
            responses = []

            for peer, response in self.tickets[ticket]:
                if response in CritErrors._value2member_map_:
                    responses.append(CritErrors(response))
                    errors.append(f"CRIT response from {peer}: {CritErrors(response)}")
                else:
                    responses.append(response)

            if not missing_receivers and len(responses) != len(receivers):
                errors.append("Unplausible amount of responses for ticket")

            self.tickets.pop(ticket, None)

            if errors:
                logger.error("\n".join(errors))
                if raise_err:
                    raise IncompleteClusterResponses("\n".join(errors))
            else:
                logger.success(f"{ticket} OK")

            return not errors, responses
