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
    Literal,
    ConnectionStatus,
)
from components.cluster.helpers import elect_leader, Peers
from components.cluster.ssl import get_ssl_context
from components.logs import logger
from components.database import *
from components.utils.cryptography import dict_digest_sha1
from components.utils.datetimes import ntime_utc_now
from components.utils import ensure_list, is_path_within_cwd


class Monitor:
    def __init__(self, cluster_instance):
        self.cluster_instance = cluster_instance
        self.tasks = set()

    async def _cleanup(self, peer):
        logger.warning(f"Removing {peer}")
        self.cluster_instance.peers.remotes[peer] = self.cluster_instance.peers.remotes[
            peer
        ].reset()
        if not self.cluster_instance._shutdown.is_set():
            async with self.cluster_instance.receiving:
                elect_leader(self.cluster_instance.peers)
                if self.cluster_instance.peers.local.swarm != "":
                    for p in self.cluster_instance.peers.local.swarm.split(";"):
                        if p != self.cluster_instance.peers.local.name:
                            try:
                                (
                                    ticket,
                                    receivers,
                                ) = await self.cluster_instance.send_command(
                                    "STATUS",
                                    p,
                                )
                            except ConnectionResetError:
                                pass

    async def _monitor(self, name):
        ireader, iwriter = self.cluster_instance.peers.remotes[name].streams._in
        timeout_c = 0
        c = -1

        logger.info(f"Evaluating stream for {name}")
        while not name in self.cluster_instance.peers.get_established():
            await asyncio.sleep(0.125)

        oreader, owriter = self.cluster_instance.peers.remotes[name].streams.out

        while True and timeout_c < 3:
            try:
                assert not all(
                    [
                        oreader.at_eof(),
                        ireader.at_eof(),
                        iwriter.is_closing(),
                        owriter.is_closing(),
                    ]
                )

                async with asyncio.timeout(defaults.CLUSTER_PEERS_TIMEOUT * 3):
                    iwriter.write(b"\x11")
                    await iwriter.drain()
                    res = await oreader.readexactly(1)
                    assert res == b"\x11"

                timeout_c = 0
                c += 0.25
                await asyncio.sleep(0.25)

                if not c % 5:
                    if (
                        not self.cluster_instance.peers.local.leader
                        or not self.cluster_instance.peers.local.swarm_complete
                    ):
                        async with self.cluster_instance.receiving:
                            try:
                                (
                                    ticket,
                                    receivers,
                                ) = await self.cluster_instance.send_command(
                                    "STATUS",
                                    "*"
                                    if self.cluster_instance.peers.local.leader
                                    and not self.cluster_instance.peers.local.swarm_complete
                                    else name,
                                )
                            except ConnectionResetError:
                                break

                            await self.cluster_instance.await_receivers(
                                ticket, receivers, raise_err=False, timeout=3
                            )
                    c = 0

            except TimeoutError:
                timeout_c += 1
                continue
            except (
                AssertionError,
                ConnectionResetError,
                asyncio.exceptions.IncompleteReadError,
            ):
                logger.error(f"Peer {name} failed")
                break

        if c != -1:
            try:
                iwriter.close()
                async with asyncio.timeout(0.1):
                    await iwriter.wait_closed()
            except (ConnectionResetError, TimeoutError):
                pass

            try:
                owriter.close()
                async with asyncio.timeout(0.1):
                    await owriter.wait_closed()
                await owriter.wait_closed()
            except (ConnectionResetError, TimeoutError):
                pass

    def _on_task_done(self, task: asyncio.Task):
        asyncio.create_task(self._cleanup(task.get_name()))
        self.tasks.discard(task)

    async def start(self, name):
        if name in [task.get_name() for task in self.tasks]:
            raise ZombiePeer(name)

        t = asyncio.create_task(self._monitor(name), name=name)
        self.tasks.add(t)
        t.add_done_callback(self._on_task_done)


class Cluster:
    def __init__(self, peers, port):
        self.locks = dict()
        self.port = port
        self.receiving = asyncio.Condition()
        self.tickets = dict()
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
                    await self.monitor.start(peer_meta["name"])
                    monitor_init = True
            except (asyncio.exceptions.IncompleteReadError, ConnectionResetError):
                break
            except TimeoutError as e:
                if str(e) == "SSL shutdown timed out":
                    break
                raise
            except ZombiePeer:
                await self.send_command(
                    CritErrors.ZOMBIE.value, peer_meta["name"], ticket=ticket
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
                        CritErrors.NOT_READY.value, peer_meta["name"], ticket=ticket
                    )

                elif cmd.startswith("PATCHTABLE") or cmd.startswith("FULLTABLE"):
                    if (
                        cmd.startswith("FULLTABLE")
                        and IN_MEMORY_DB["PEER_CRIT"].get(peer_meta["name"])
                        == "CRIT:TABLE_HASH_MISMATCH"
                    ):
                        IN_MEMORY_DB["PEER_CRIT"].pop(peer_meta["name"], None)

                    if (
                        cmd.startswith("PATCHTABLE")
                        and IN_MEMORY_DB["PEER_CRIT"].get(peer_meta["name"])
                        == "CRIT:TABLE_HASH_MISMATCH"
                    ):
                        await self.send_command(
                            CritErrors.NO_TRUST.value,
                            peer_meta["name"],
                            ticket=ticket,
                        )
                        continue

                    _, _, payload = cmd.partition(" ")
                    table_w_hash, table_payload = payload.split(" ")
                    table, table_digest = table_w_hash.split("@")
                    db_params = evaluate_db_params(ticket)

                    async with TinyDB(**db_params) as db:
                        if not table in db.tables():
                            await self.send_command(
                                CritErrors.NO_SUCH_TABLE.value,
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
                                            CritErrors.TABLE_HASH_MISMATCH.value,
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
                                                CritErrors.DOC_MISMATCH.value,
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
                                    CritErrors.CANNOT_APPLY.value,
                                    peer_meta["name"],
                                    ticket=ticket,
                                )
                                continue

                elif cmd == "COMMIT":
                    if not ticket in self._session_patched_tables:
                        await self.send_command(
                            CritErrors.NOTHING_TO_COMMIT.value,
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
                    logger.warning(
                        "{name} left the cluster".format(name=peer_meta["name"])
                    )
                    self.peers.remotes[peer_meta["name"]] = self.peers.remotes[
                        peer_meta["name"]
                    ].reset()

                elif cmd.startswith("FILEGET"):
                    _, _, payload = cmd.partition(" ")
                    start, end, file = payload.split(" ")

                    if not is_path_within_cwd(file) or not os.path.exists(file):
                        await self.send_command(
                            CritErrors.INVALID_FILE_PATH.value,
                            peer_meta["name"],
                            ticket=ticket,
                        )
                        continue

                    if os.stat(file).st_size < int(start):
                        await self.send_command(
                            CritErrors.START_BEHIND_FILE_END.value,
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

                    await self.send_command(
                        f"ACK {file} {compressed_data_encoded}",
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
                        logger.error(
                            f'Rejecting LOCK for {peer_meta["name"]} due to inconsistent connections'
                        )
                        await self.send_command(
                            CritErrors.PEERS_MISMATCH.value,
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
                        for t in tables:
                            if ntime_utc_now() - float(self.locks[t]["ticket"]) > 60.0:
                                with suppress(RuntimeError):
                                    self.locks[t]["lock"].release()
                                self.locks[t]["ticket"] = None

                        await self.send_command(
                            "ACK BUSY", peer_meta["name"], ticket=ticket
                        )
                    else:
                        await self.send_command("ACK", peer_meta["name"], ticket=ticket)

                elif cmd.startswith("ACK"):
                    _, _, payload = cmd.partition(" ")
                    if ticket in self.tickets:
                        self.tickets[ticket].add((peer_meta["name"], payload))

                async with self.receiving:
                    elect_leader(self.peers)
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
                status, con = await self.peers.remotes[name].connect()
                if status == ConnectionStatus.CONNECTED:
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
                    logger.warning(f"Cannot send to peer {name} - {status}: {con}")

        return ticket, successful_receivers

    async def release(self, tables: list = ["main"]) -> str:
        errors = []
        CTX_TICKET.reset(self._ctx_ticket)

        if self.peers.local.role == Role.FOLLOWER:
            async with self.receiving:
                try:
                    ticket, receivers = await self.send_command(
                        f"UNLOCK {','.join(tables)}",
                        self.peers.local.leader,
                    )
                    ret, responses = await self.await_receivers(
                        ticket, receivers, raise_err=True
                    )
                except IncompleteClusterResponses:
                    errors.append("master_not_reachable")

        for t in tables:
            with suppress(RuntimeError):
                self.locks[t]["lock"].release()
            self.locks[t]["ticket"] = None

        if "master_not_reachable" in errors:
            async with self.receiving:
                ticket, receivers = await self.send_command("STATUS", "*")
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

                await asyncio.wait_for(self.locks[t]["lock"].acquire(), 60.0)
                self.locks[t]["ticket"] = ticket

        except TimeoutError:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()

            raise DistLockCancelled("Unable to acquire local lock")

        errors = []
        if self.peers.local.role == Role.FOLLOWER:
            async with self.receiving:
                try:
                    if not self.peers.local.leader:
                        raise IncompleteClusterResponses

                    ticket, receivers = await self.send_command(
                        f"LOCK {','.join(tables)}", self.peers.local.leader
                    )
                    result, responses = await self.await_receivers(
                        ticket, receivers, raise_err=True
                    )
                    if "BUSY" in responses:
                        errors.append("master_busy")

                    if (
                        IN_MEMORY_DB["PEER_CRIT"].get(self.peers.local.leader)
                        == "CRIT:PEERS_MISMATCH"
                    ):
                        IN_MEMORY_DB["PEER_CRIT"][self.peers.local.leader] = None

                except asyncio.CancelledError:
                    errors.append("lock_cancelled")
                except IncompleteClusterResponses:
                    if (
                        IN_MEMORY_DB["PEER_CRIT"].get(self.peers.local.leader)
                        == "CRIT:PEERS_MISMATCH"
                    ):
                        errors.append("lock_rejected")
                    else:
                        errors.append("master_not_reachable")

        if "master_busy" in errors:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()
            return await self.acquire_lock(tables)

        if "lock_rejected" in errors:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()
            async with self.receiving:
                ticket, receivers = await self.send_command("STATUS", "*")
                await self.await_receivers(ticket, receivers, raise_err=False)
            raise DistLockCancelled("Master rejected LOCK due to inconsistency")

        if "lock_cancelled" in errors:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()
            raise DistLockCancelled("Lock was cancelled")

        if "master_not_reachable" in errors:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()
            async with self.receiving:
                ticket, receivers = await self.send_command("STATUS", "*")
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
        async with self.receiving:
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
                                peer_start = os.stat(
                                    f"peer_files/{peer}/{file}"
                                ).st_size
                            else:
                                peer_start = 0

                        ticket, receivers = await self.send_command(
                            f"FILEGET {peer_start} {peer_end} {file}", peer
                        )
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
            async with self.receiving:
                for peer in self.peers.remotes:
                    with closing(
                        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ) as sock:
                        sock.settimeout(defaults.CLUSTER_PEERS_TIMEOUT)
                        if (
                            sock.connect_ex(
                                (
                                    self.peers.get_remote_peer_ip(
                                        name=peer, ip_version="best"
                                    ),
                                    self.port,
                                )
                            )
                            == 0
                        ):
                            ticket, receivers = await self.send_command("INIT", peer)
                            ret, responses = await self.await_receivers(
                                ticket, receivers, raise_err=False
                            )
                            if "CRIT:ZOMBIE" in responses:
                                shutdown_trigger.set()
                                break
            try:
                await shutdown_trigger.wait()
            except asyncio.CancelledError:
                async with self.receiving:
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
            responses = [response for _, response in self.tickets[ticket]]
            critical_errors = {p: m for p, m in self.tickets[ticket] if "CRIT" in m}

            for peer, critical_error in critical_errors.items():
                IN_MEMORY_DB["PEER_CRIT"][peer] = critical_error
                errors.append(f"{peer} reported a critical error: {critical_error}")

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
