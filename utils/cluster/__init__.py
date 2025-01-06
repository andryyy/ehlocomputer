import asyncio
import fileinput
import json
import os
import random
import re
import socket
import ssl
import zlib
import base64
import sys

from config import defaults
from config.database import *
from config.logs import logger
from contextlib import closing, suppress
from deepdiff import Delta
from enum import Enum
from tools import CONTEXT_TRANSACTION, evaluate_db_params
from utils.crypto import sha256_filedigest
from utils.datetimes import ntime_utc_now
from utils.helpers import ensure_list, read_n_to_last_line, is_path_within_cwd
from uuid import uuid4


StreamPair = tuple[asyncio.StreamReader, asyncio.StreamWriter]


def get_ssl_context(type_value: str):
    if type_value == "client":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    elif type_value == "server":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    else:
        raise Exception("Unknown type_value")

    context.load_cert_chain(
        certfile=defaults.TLS_CERTFILE, keyfile=defaults.TLS_KEYFILE
    )
    context.load_verify_locations(cafile=defaults.TLS_CA)
    context.check_hostname = False
    context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


class DistLockCancelled(Exception):
    pass


class IncompleteClusterResponses(Exception):
    pass


class Role(Enum):
    MASTER = 1
    SLAVE = 0


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
        self.server_init = False

        IN_MEMORY_DB["peer_failures"] = dict()

    def _set_master_node(self):
        def _destroy():
            self.master_node = None
            self.role = Role.SLAVE
            self.server_init = False

        established = [k for k, v in self.connections.items() if v["meta"]]
        n_online_peers = len(established) + 1
        n_all_peers = len(defaults.CLUSTER_PEERS_THEM) + 1

        current_master_node = self.master_node

        if not (n_online_peers >= (51 / 100) * n_all_peers):
            logger.info("<set_master_node> skipping election, not enough peers")
            _destroy()
            return

        master_node, started = min(
            (
                (peer, float(data["meta"]["started"]))
                for peer, data in self.connections.items()
                if data.get("meta")
            ),
            key=lambda x: x[1],
            default=(None, float("inf")),  # Default value if no valid entries are found
        )

        if self.started < started:  # donkey elects itself
            if self.master_node != defaults.CLUSTER_PEERS_ME:
                logger.info(
                    f"<set_master_node> elected self ({defaults.CLUSTER_PEERS_ME}) as master"
                )
                self.server_init = True
                self.master_node = defaults.CLUSTER_PEERS_ME
                self.role = Role.MASTER

        else:
            their_master = self.connections[master_node]["meta"]["master"]

            if their_master == "?CONFUSED":
                _destroy()
                logger.info(
                    f"<set_master_node> potential master {master_node} is still confused, waiting"
                )
                return

            if their_master != master_node:
                _destroy()
                logger.warning(
                    f"<set_master_node> not electing {master_node}:"
                    + "node reports different master (are we still joining or changed our swarm size?) - "
                    + "waiting"
                )
                return

            if self.master_node != master_node:
                self.server_init = True
                self.master_node = master_node
                self.role = Role.SLAVE
                logger.info(
                    f"<set_master_node> elected foreign peer {self.master_node} as master"
                )

        logger.debug(
            f"<set_master_node> our swarm has {n_online_peers}/{n_all_peers} worms"
        )

    def log_rx(self, peer: str, msg: str, max_msg_len=200):
        msg = msg[:max_msg_len] + (msg[max_msg_len:] and "...")
        logger.debug(f"(Rx) {defaults.CLUSTER_PEERS_ME} ← {peer}: {msg}")

    def _log_tx(self, peer: str, msg: str, max_msg_len=200):
        msg = msg[:max_msg_len] + (msg[max_msg_len:] and "...")
        logger.debug(f"(Tx) {defaults.CLUSTER_PEERS_ME} → {peer}: {msg}")

    async def _send(
        self,
        streams: StreamPair,
        ticket: str,
        cmd: str,
    ) -> None:
        reader, writer = streams

        if reader.at_eof() or writer.is_closing():
            raise Exception("Unexpected disconnect")

        raddr, _ = writer.get_extra_info("peername")

        buffer_data = [
            ticket,
            cmd,
            "META",
            f"NAME {defaults.NODENAME}",
            f"STARTED {self.started}",
            "MASTER {master_node}".format(master_node=self.master_node or "?CONFUSED"),
            f"BIND {defaults.CLUSTER_PEERS_ME}",
        ]

        buffer_bytes = " ".join(buffer_data).encode("utf-8")
        writer.write(len(buffer_bytes).to_bytes(4, "big"))
        writer.write(buffer_bytes)

        await writer.drain()

        self._log_tx(raddr, cmd)

    async def _recv(self, streams: StreamPair) -> str:
        reader, writer = streams

        bytes_to_read = int.from_bytes(await reader.readexactly(4), "big")
        input_bytes = await reader.readexactly(bytes_to_read)

        input_decoded = input_bytes.strip().decode("utf-8")
        data, _, meta = input_decoded.partition(" META ")
        ticket, _, cmd = data.partition(" ")

        patterns = [
            r"NAME (?P<name>\S+)",
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

        self.log_rx(
            "{bind}[{node}]".format(bind=meta_dict["bind"], node=meta_dict["name"]),
            f"Ticket {ticket}, Command {cmd}",
        )

        return ticket, cmd, meta_dict

    async def connection_handler(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        raddr, *_ = writer.get_extra_info("peername")
        socket, *_ = writer.get_extra_info("socket").getsockname()

        if socket and raddr in defaults.CLUSTER_CLI_BINDINGS:
            return await self._cli_processor((reader, writer))

        while True:
            try:
                ticket, cmd, peer_info = await self._recv((reader, writer))
                self._set_master_node()
                IN_MEMORY_DB["peer_failures"][peer_info["bind"]] = 0
                if ((ntime_utc_now() - float(ticket)) > 5.0) and not cmd.startswith(
                    "RTASK"
                ):
                    continue
            except asyncio.exceptions.IncompleteReadError:
                async with self.receiving:
                    ticket, receivers = await self.send_command("STATUS", "*")
                    await self._await_receivers(ticket, receivers, raise_on_error=False)
                    self._set_master_node()
                    break

            try:
                if not self.server_init and not any(
                    map(lambda s: cmd.startswith(s), ["ACK", "STATUS", "APPLY", "INIT"])
                ):
                    await self.send_command(
                        "ACK CRIT:NOT_READY", [peer_info["bind"]], ticket=ticket
                    )

                # A task starting with "R" indicates a resync
                elif cmd.startswith("APPLY"):
                    _, _, payload = cmd.partition(" ")
                    table, delta_payload = payload.split(" ")
                    table_delta = Delta(base64.b64decode(delta_payload), safe_to_import="tinydb.table.Document")
                    db_params = evaluate_db_params(ticket)
                    async with TinyDB(**db_params) as db:
                        if not table in db.tables():
                            await self.send_command(
                                "ACK CRIT:NO_SUCH_TABLE", [peer_info["bind"]], ticket=ticket
                            )
                        else:
                            try:
                                table_data = db.table(table).all()
                                db.table(table).truncate()
                                db.table(table).insert_multiple(table_data + table_delta)
                                await self.send_command("ACK", [peer_info["bind"]], ticket=ticket)
                            except Exception as e:
                                logger.error(f"<connection_handler> {type(e)}: {e}")
                                await self.send_command("CRIT:CANNOT_APPLY", [peer_info["bind"]], ticket=ticket)

                elif cmd == "COMMIT":
                    db_params = evaluate_db_params(ticket)
                    if not os.path.isfile(db_params["filename"]):
                        await self.send_command("CRIT:NOTHING_TO_COMMIT", [peer_info["bind"]], ticket=ticket)
                    else:
                        async with TinyDB(**db_params) as db:  # acquires tinydbs lock
                            os.rename(db_params["filename"], TINYDB_PARAMS["filename"])
                        await self.send_command("ACK", [peer_info["bind"]], ticket=ticket)

                elif (cmd == "STATUS" or cmd == "INIT"):
                    await self.send_command("ACK", [peer_info["bind"]], ticket=ticket)

                elif cmd.startswith("FILEGET"):
                    _, _, payload = cmd.partition(" ")
                    if not is_path_within_cwd(payload):
                        await self.send_command(
                            "ACK CRIT:INVALID_FILE_PATH",
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

                    try:
                        for t in tables:
                            if t not in self.locks:
                                self.locks[t] = {
                                    "lock": asyncio.Lock(),
                                    "ticket": None,
                                }

                            await asyncio.wait_for(self.locks[t]["lock"].acquire(), 0.45)
                            self.locks[t]["ticket"] = ticket

                    except TimeoutError:
                        for t in tables:
                            if ntime_utc_now() - float(self.locks[t]["ticket"]) > 20.0:
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
                    self.receiving.notify_all()

            except Exception as e:
                logger.error(f"<connection_handler> {type(e)}: {e}")

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
            if peer not in IN_MEMORY_DB["peer_failures"]:
                IN_MEMORY_DB["peer_failures"][peer] = 0
            elif IN_MEMORY_DB["peer_failures"][peer] > defaults.CLUSTER_PEER_MAX_FAILURES:
                logger.warning(
                    f"<send_command> not trying peer {peer} due to {IN_MEMORY_DB["peer_failures"][peer]} failed connection attempts"
                )
                continue

            if not peer in self.connections:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                    sock.settimeout(defaults.CLUSTER_PEERS_TIMEOUT)
                    if sock.connect_ex((peer, self.port)) != 0:
                        logger.warning(f"<{peer}> Connection timed out")
                        IN_MEMORY_DB["peer_failures"][peer] += 1
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
                    IN_MEMORY_DB["peer_failures"][peer] = 0
                except ConnectionRefusedError:
                    if IN_MEMORY_DB["peer_failures"][peer] == 0:
                        logger.warning(f"<{peer}> ConnectionRefusedError")
                    IN_MEMORY_DB["peer_failures"][peer] += 1

            if self.connections[peer]["streams"]:
                try:
                    await self._send(self.connections[peer]["streams"], ticket, cmd)
                    successful_receivers.append(peer)
                except Exception as e:
                    logger.error(f"<{peer}> disconnected ({type(e)}: {e})")
                    del self.connections[peer]

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
                    ret, responses = await self._await_receivers(
                        ticket, receivers, raise_on_error=True
                    )
                except IncompleteClusterResponses:
                    errors.append("master_not_reachable")


        for t in tables:
            with suppress(RuntimeError):
                self.locks[t]["lock"].release()
            self.locks[t]["ticket"] = None

        if "remote_transaction_failed" in errors:
            logger.error(
                f"<tasks> a task failed to replicate, not committing transaction"
            )

        if "master_not_reachable" in errors:
            async with self.receiving:
                ticket, receivers = await self.send_command("STATUS", "*")
                await self._await_receivers(ticket, receivers, raise_on_error=False)
            raise DistLockCancelled("Master re-election")

    async def acquire_lock(self, tables: list = ["main"]) -> str:
        try:
            ticket = str(ntime_utc_now())
            for t in tables:
                if t not in self.locks:
                    self.locks[t] = {
                        "lock": asyncio.Lock(),
                        "ticket": None,
                    }

                await asyncio.wait_for(self.locks[t]["lock"].acquire(), 3.0)
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
                    result, responses = await self._await_receivers(
                        ticket, receivers, raise_on_error=True
                    )
                    if "BUSY" in responses:
                        errors.append("master_busy")
                except asyncio.CancelledError:
                    errors.append("lock_cancelled")
                except IncompleteClusterResponses:
                    errors.append("master_not_reachable")

        if "master_busy" in errors:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()
            return await self.acquire_lock(tables)

        if "lock_cancelled" in errors:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()
            errors.append("master_not_reachable")

        if "master_not_reachable" in errors:
            for t in tables:
                with suppress(RuntimeError):
                    self.locks[t]["lock"].release()
            async with self.receiving:
                ticket, receivers = await self.send_command("STATUS", "*")
                await self._await_receivers(ticket, receivers, raise_on_error=False)
            raise DistLockCancelled("Master re-election")

        self._context_token = CONTEXT_TRANSACTION.set(ntime_utc_now())

    async def request_files(self, files: str | list, peers="*"):
        files = ensure_list(files)
        async with self.receiving:
            try:
                for file in files:
                    if not is_path_within_cwd(file):
                        logger.error(f"<request_files> file not within cwd: {file}")
                        continue

                    ticket, receivers = await self.send_command(
                        f"FILEGET {file}", peers
                    )
                    _, responses = await self._await_receivers(
                        ticket, receivers, raise_on_error=True
                    )

                    for r in responses:
                        r_file, r_peer, r_data = r.split(" ")
                        assert r_file == file
                        assert r_peer in defaults.CLUSTER_PEERS_THEM
                        file_dest = f"peer_files/{r_peer}/{file}"
                        os.makedirs(os.path.dirname(file_dest), exist_ok=True)
                        payload = zlib.decompress(base64.b64decode(r_data))
                        with open(file_dest, "wb") as f:
                            f.write(payload)
            except IncompleteClusterResponses:
                logger.error(
                    f"<request_files> sending command to peers '{peers}'' failed"
                )
            except Exception as e:
                logger.error(f"<request_files> unhandled error: {e}")

    async def run(self, shutdown_trigger) -> None:
        server = await asyncio.start_server(
            self.connection_handler,
            self.host,
            self.port,
            ssl=get_ssl_context("server"),
            limit=10485760,  # 10 MiB
        )

        logger.info(f"Listening on {self.port} on address {" and ".join(self.host)}...")

        status = False
        while not status or not self.server_init:
            async with self.receiving:
                ticket, receivers = await self.send_command("INIT", "*")
                status, responses = await self._await_receivers(ticket, receivers, raise_on_error=False)
                if status:
                    self._set_master_node()
                if not self.server_init:
                    await asyncio.sleep(1.0)

        async with server:
            await shutdown_trigger.wait()

    async def _await_receivers(self, ticket, receivers, raise_on_error: bool):
        _err_msg = None
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
            _err_msg = f"missing receviers: {", ".join(missing_receivers)}"
        finally:
            responses = [response for _, response in self.tickets[ticket]]
            crit_responses = [s for s in responses if "CRIT" in s]

            if len(responses) != len(receivers):
                _err_msg = "unplausible amount of responses for ticket"

            if crit_responses:
                _err_msg = f"one or more peers reported CRIT: {self.tickets[ticket]}"

            del self.tickets[ticket]

            if _err_msg:
                logger.error(_err_msg)
                if raise_on_error:
                    raise IncompleteClusterResponses(f"<{ticket}> {_err_msg}")
            else:
                logger.success(f"<{ticket}> ticket confirmed")

            return not _err_msg, responses

    async def _cli_processor(self, streams: StreamPair):
        try:
            reader, writer = streams
            while not reader.at_eof():
                cmd = await reader.readexactly(1)
                if cmd == b"\x97":
                    data = await reader.readuntil(b"\n")
                    user = data.strip().decode("utf-8")
                    try:
                        user = await Users.user(login=user).get()
                        if "system" not in user.acl:
                            user.acl.append("system")
                            await Users.user(login=user).patch(data={"acl": user.acl})
                            writer.write(b"\x01")
                        else:
                            writer.write(b"\x02")
                    except:
                        writer.write(b"\x03")
                    await writer.drain()
                elif cmd == b"\x98":
                    awaiting = dict()
                    idx = 1
                    for k, v in IN_MEMORY_DB.items():
                        if isinstance(v, dict) and v.get("status") == "awaiting":
                            awaiting[idx] = (k, v["intention"])
                            idx += 1
                    writer.write(f"{json.dumps(awaiting)}\n".encode("ascii"))
                    await writer.drain()
                elif cmd == b"\x99":
                    data = await reader.readexactly(14)
                    confirmed = data.strip().decode("ascii")
                    code = "%06d" % random.randint(0, 999999)
                    IN_MEMORY_DB.get(confirmed, {}).update(
                        {"status": "confirmed", "code": code}
                    )
                    writer.write(f"{code}\n".encode("ascii"))
                    await writer.drain()
        except Exception as e:
            if type(e) not in [
                asyncio.exceptions.IncompleteReadError,
                ConnectionResetError,
            ]:
                raise
        finally:
            writer.close()
            await writer.wait_closed()
