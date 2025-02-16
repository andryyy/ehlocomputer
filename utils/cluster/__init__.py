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
from config.database import *
from config.logs import logger
from contextlib import closing, suppress
from utils.cluster.exceptions import IncompleteClusterResponses, DistLockCancelled
from utils.cluster.cli import cli_processor
from utils.cluster.helpers import (
    set_master_node,
    get_ssl_context,
    log_rx,
    log_tx,
    CritErrors,
    Role,
)
from tools import CONTEXT_TRANSACTION, evaluate_db_params
from utils.crypto import dict_digest_sha1
from utils.datetimes import ntime_utc_now
from utils.helpers import ensure_list, is_path_within_cwd
from typing import Literal
from pydantic import FilePath, validate_call


class Cluster:
    def __init__(self, host, port):
        assert isinstance(host, str) or isinstance(host, list)
        assert isinstance(defaults.CLUSTER_CLI_BINDINGS, list)

        self.connections = dict()
        self.host = ensure_list(host) + defaults.CLUSTER_CLI_BINDINGS
        self.locks = dict()
        self.master_node = None
        self.port = port
        self.receiving = asyncio.Condition()
        self.role = Role.SLAVE
        self.started = ntime_utc_now()
        self.tickets = dict()
        self.connected_nodes = None

        IN_MEMORY_DB["connection_failures"] = dict()
        IN_MEMORY_DB["peer_critical"] = dict()

    async def send(
        self,
        streams: tuple[asyncio.StreamReader, asyncio.StreamWriter],
        ticket: str,
        cmd: str,
    ) -> None:
        reader, writer = streams
        if reader.at_eof():
            writer.close()
            await writer.wait_closed()
            raise Exception("Reader at EOF")

        if writer.is_closing():
            raise Exception("Writer is closing")

        raddr, _ = writer.get_extra_info("peername")

        buffer_data = [
            ticket,
            cmd,
            "META",
            f"NAME {defaults.CLUSTER_NODENAME}",
            "CONNECTIONS {connected_nodes}".format(
                connected_nodes=self.connected_nodes or "?CONFUSED"
            ),
            f"STARTED {self.started}",
            "MASTER {master_node}".format(master_node=self.master_node or "?CONFUSED"),
            f"BIND {defaults.CLUSTER_PEERS_ME}",
        ]

        buffer_bytes = " ".join(buffer_data).encode("utf-8")
        writer.write(len(buffer_bytes).to_bytes(4, "big"))
        writer.write(buffer_bytes)
        await writer.drain()
        log_tx(raddr, cmd)

    async def receive(self, reader: asyncio.StreamReader) -> tuple[str, str, dict]:
        bytes_to_read = int.from_bytes(await reader.readexactly(4), "big")
        input_bytes = await reader.readexactly(bytes_to_read)

        input_decoded = input_bytes.strip().decode("utf-8")
        data, _, meta = input_decoded.partition(" META ")
        ticket, _, cmd = data.partition(" ")

        patterns = [
            r"NAME (?P<name>\S+)",
            r"CONNECTIONS (?P<connections>\S+)",
            r"STARTED (?P<started>\S+)",
            r"MASTER (?P<master>\S+)",
            r"BIND (?P<bind>\S+)",
        ]

        match = re.search(" ".join(patterns), meta)
        meta_dict = match.groupdict()

        if not meta_dict["bind"] in self.connections:
            self.connections[meta_dict["bind"]] = {
                "meta": meta_dict,
                "streams": set(),
            }
        else:
            self.connections[meta_dict["bind"]]["meta"] = meta_dict

        log_rx(
            "{bind}[{node}]".format(bind=meta_dict["bind"], node=meta_dict["name"]),
            f"Ticket {ticket}, Command {cmd}",
        )

        return ticket, cmd, meta_dict

    async def connection_handler(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        raddr, *_ = writer.get_extra_info("peername")
        socket, *_ = writer.get_extra_info("socket").getsockname()
        peer_info = {}

        if socket and raddr in defaults.CLUSTER_CLI_BINDINGS:
            return await cli_processor((reader, writer))

        while True:
            try:
                ticket, cmd, peer_info = await self.receive(reader)
                if IN_MEMORY_DB["connection_failures"].get(peer_info["bind"], 0) > 0:
                    logger.success(f"Peer {peer_info['bind']} recovered")
                IN_MEMORY_DB["connection_failures"][peer_info["bind"]] = 0
            except asyncio.exceptions.IncompleteReadError:
                async with self.receiving:
                    writer.close()
                    await writer.wait_closed()
                    ticket, receivers = await self.send_command("STATUS", "*")
                    await self.await_receivers(ticket, receivers, raise_err=False)
                    break

            try:
                if not self.master_node and not any(
                    map(
                        lambda s: cmd.startswith(s),
                        ["ACK", "STATUS", "FULLTABLE", "INIT"],
                    )
                ):
                    await self.send_command(
                        CritErrors.NOT_READY.value, [peer_info["bind"]], ticket=ticket
                    )

                elif cmd.startswith("PATCHTABLE") or cmd.startswith("FULLTABLE"):
                    if (
                        cmd.startswith("FULLTABLE")
                        and IN_MEMORY_DB["peer_critical"].get(peer_info["bind"])
                        == "CRIT:TABLE_HASH_MISMATCH"
                    ):
                        IN_MEMORY_DB["peer_critical"].pop(peer_info["bind"], None)

                    if (
                        cmd.startswith("PATCHTABLE")
                        and IN_MEMORY_DB["peer_critical"].get(peer_info["bind"])
                        == "CRIT:TABLE_HASH_MISMATCH"
                    ):
                        await self.send_command(
                            CritErrors.NO_TRUST.value,
                            [peer_info["bind"]],
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
                                [peer_info["bind"]],
                                ticket=ticket,
                            )
                        else:
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
                                            [peer_info["bind"]],
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
                                                [peer_info["bind"]],
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
                                    "ACK", [peer_info["bind"]], ticket=ticket
                                )

                            except Exception as e:
                                await self.send_command(
                                    CritErrors.CANNOT_APPLY.value,
                                    [peer_info["bind"]],
                                    ticket=ticket,
                                )
                                continue

                elif cmd == "COMMIT":
                    db_params = evaluate_db_params(ticket)
                    if not os.path.isfile(db_params["filename"]):
                        await self.send_command(
                            CritErrors.NOTHING_TO_COMMIT.value,
                            [peer_info["bind"]],
                            ticket=ticket,
                        )
                    else:
                        async with TinyDB(**db_params) as db:  # acquires tinydbs lock
                            os.rename(db_params["filename"], TINYDB_PARAMS["filename"])
                        await self.send_command(
                            "ACK", [peer_info["bind"]], ticket=ticket
                        )

                elif cmd == "STATUS" or cmd == "INIT":
                    await self.send_command("ACK", [peer_info["bind"]], ticket=ticket)

                elif cmd.startswith("FILEGET"):
                    _, _, payload = cmd.partition(" ")
                    if not is_path_within_cwd(payload):
                        await self.send_command(
                            CritErrors.INVALID_FILE_PATH.value,
                            [peer_info["bind"]],
                            ticket=ticket,
                        )
                    else:
                        with open(payload, "rb") as f:
                            compressed_data = zlib.compress(f.read())
                            compressed_data_encoded = base64.b64encode(
                                compressed_data
                            ).decode("utf-8")

                        await self.send_command(
                            f"ACK {payload} {defaults.CLUSTER_PEERS_ME} {compressed_data_encoded}",
                            [peer_info["bind"]],
                            ticket=ticket,
                        )

                elif cmd.startswith("UNLOCK"):
                    _, _, tables_str = cmd.partition(" ")
                    tables = tables_str.split(",")

                    for t in tables:
                        with suppress(RuntimeError):
                            self.locks[t]["lock"].release()
                        self.locks[t]["ticket"] = None

                    await self.send_command("ACK", [peer_info["bind"]], ticket=ticket)

                elif cmd.startswith("LOCK"):
                    _, _, tables_str = cmd.partition(" ")
                    tables = tables_str.split(",")

                    peer_connections = [
                        c
                        for c in peer_info["connections"].split(";")
                        if c != defaults.CLUSTER_PEERS_ME
                    ] + [peer_info["bind"]]

                    if set(peer_connections) != set(self.connected_nodes.split(";")):
                        logger.error(
                            f'Rejecting LOCK for {peer_info["bind"]} due to inconsistent connections'
                        )
                        await self.send_command(
                            CritErrors.PEERS_MISMATCH.value,
                            [peer_info["bind"]],
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
                            "ACK BUSY", [peer_info["bind"]], ticket=ticket
                        )
                    else:
                        await self.send_command(
                            "ACK", [peer_info["bind"]], ticket=ticket
                        )

                elif cmd.startswith("ACK"):
                    _, _, payload = cmd.partition(" ")
                    if ticket in self.tickets:
                        self.tickets[ticket].add((peer_info["bind"], payload))

                async with self.receiving:
                    set_master_node(self)
                    self.receiving.notify_all()

            except Exception as e:
                logger.error(f"{type(e)}: {e}")

    async def send_command(self, cmd, peers, ticket: str | None = None):
        if not ticket:
            ticket = str(ntime_utc_now())
        if peers == "*":
            receivers = defaults.CLUSTER_PEERS_THEM
        else:
            receivers = []
            for p in peers:
                if p in defaults.CLUSTER_PEERS_THEM:
                    receivers.append(p)
                elif p in self.connections.keys():
                    receivers.append(self.connections[p]["meta"]["bind"])

        if ticket not in self.tickets:
            self.tickets[ticket] = set()

        successful_receivers = []

        for peer in receivers:
            if peer not in IN_MEMORY_DB["connection_failures"]:
                IN_MEMORY_DB["connection_failures"][peer] = 0
            elif (
                IN_MEMORY_DB["connection_failures"][peer]
                > defaults.CLUSTER_PEER_MAX_FAILURES
            ):
                logger.warning(f"Not trying peer {peer} due to consecutive failures")
                continue

            if not peer in self.connections:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                    sock.settimeout(defaults.CLUSTER_PEERS_TIMEOUT)
                    if sock.connect_ex((peer, self.port)) != 0:
                        logger.warning(f"Skipping {peer}: Connection timed out")
                        IN_MEMORY_DB["connection_failures"][peer] += 1
                        continue

                self.connections[peer] = {
                    "meta": dict(),
                    "streams": set(),
                }

            if not self.connections[peer].get("streams"):
                try:
                    self.connections[peer]["streams"] = await asyncio.open_connection(
                        peer, self.port, ssl=get_ssl_context("client")
                    )
                    IN_MEMORY_DB["connection_failures"][peer] = 0
                except ConnectionRefusedError:
                    if IN_MEMORY_DB["connection_failures"][peer] == 0:
                        logger.warning(f"Skipping {peer}: ConnectionRefusedError")
                    IN_MEMORY_DB["connection_failures"][peer] += 1
                    continue

            try:
                await self.send(self.connections[peer]["streams"], ticket, cmd)
                successful_receivers.append(peer)
            except Exception as e:
                logger.warning(
                    f"Disconnecting and cleaning up connection to {peer}: {e})"
                )
                _, writer = self.connections[peer]["streams"]
                writer.close()
                await writer.wait_closed()
                self.connections.pop(peer, None)
                set_master_node(self)

        return ticket, successful_receivers

    async def release(self, tables: list = ["main"]) -> str:
        errors = []

        CONTEXT_TRANSACTION.reset(self._context_token)

        if self.role == Role.SLAVE:
            async with self.receiving:
                try:
                    ticket, receivers = await self.send_command(
                        f"UNLOCK {','.join(tables)}", [self.master_node]
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
        if self.role == Role.SLAVE:
            async with self.receiving:
                try:
                    if not self.master_node:
                        raise IncompleteClusterResponses

                    ticket, receivers = await self.send_command(
                        f"LOCK {','.join(tables)}", [self.master_node]
                    )
                    result, responses = await self.await_receivers(
                        ticket, receivers, raise_err=True
                    )
                    if "BUSY" in responses:
                        errors.append("master_busy")

                    if (
                        IN_MEMORY_DB["peer_critical"].get(self.master_node)
                        == "CRIT:PEERS_MISMATCH"
                    ):
                        IN_MEMORY_DB["peer_critical"][self.master_node] = None

                except asyncio.CancelledError:
                    errors.append("lock_cancelled")
                except IncompleteClusterResponses:
                    if (
                        IN_MEMORY_DB["peer_critical"].get(self.master_node)
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

        self._context_token = CONTEXT_TRANSACTION.set(ntime_utc_now())

    @validate_call
    async def request_files(
        self, files: FilePath | list[FilePath], peers: Literal["*"] | list
    ):
        assert self.locks["files"]["lock"].locked()
        async with self.receiving:
            for file in ensure_list(files):
                try:
                    if not is_path_within_cwd(file):
                        logger.error(f"File not within cwd: {file}")
                        continue

                    ticket, receivers = await self.send_command(
                        f"FILEGET {file}", peers
                    )
                    _, responses = await self.await_receivers(
                        ticket, receivers, raise_err=True
                    )

                    for r in responses:
                        r_file, r_peer, r_data = r.split(" ")
                        assert FilePath(r_file) == file
                        assert r_peer in defaults.CLUSTER_PEERS_THEM
                        file_dest = f"peer_files/{r_peer}/{file}"
                        os.makedirs(os.path.dirname(file_dest), exist_ok=True)
                        payload = zlib.decompress(base64.b64decode(r_data))
                        with open(file_dest, "wb") as f:
                            f.write(payload)

                except IncompleteClusterResponses:
                    logger.error(f"Sending command to peers '{peers}' failed")
                    raise
                except Exception as e:
                    logger.error(f"Unhandled error: {e}")
                    raise

    async def run(self, shutdown_trigger) -> None:
        server = await asyncio.start_server(
            self.connection_handler,
            self.host,
            self.port,
            ssl=get_ssl_context("server"),
            limit=10485760,  # 10 MiB
        )

        logger.info(f"Listening on {self.port} on address {' and '.join(self.host)}...")

        while not self.master_node:
            for peer in defaults.CLUSTER_PEERS_THEM:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                    sock.settimeout(defaults.CLUSTER_PEERS_TIMEOUT)
                    if sock.connect_ex((peer, self.port)) == 0:
                        async with self.receiving:
                            ticket, receivers = await self.send_command("INIT", [peer])
                            self.tickets.pop(ticket, None)
                    continue
            await asyncio.sleep(0.5)

        async with server:
            await shutdown_trigger.wait()

    async def await_receivers(self, ticket, receivers, raise_err: bool):
        errors = []
        missing_receivers = []
        try:
            while not all(
                r in [peer for peer, _ in self.tickets[ticket]] for r in receivers
            ):
                await asyncio.wait_for(self.receiving.wait(), 2.25)
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
                IN_MEMORY_DB["peer_critical"][peer] = critical_error
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
