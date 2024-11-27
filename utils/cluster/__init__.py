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
from config.database import IN_MEMORY_DB
from config.logs import logger
from contextlib import closing, suppress
from enum import Enum
from tools import CONTEXT_TRANSACTION, TaskModel
from tools.objects import Objects
from tools.users import Users
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


class Transaction:
    def __init__(self):
        from threading import Lock

        self.trans_fn = "database/.transactions"
        self.commits_fn = "database/.commits"
        self.db_fn = "database/main"
        self.lock = Lock()

        for fn in [self.trans_fn, self.commits_fn, self.db_fn]:
            if not os.path.exists(fn):
                with open(fn, "x"):
                    pass
            os.chmod(fn, 0o600)

    def _process_data(self, data):
        if not data:
            return "0.0", ""

        transaction, commit_on, payload = data.strip().split(":", 2)
        TaskModel.parse_raw_task(payload)

        return transaction, payload

    @property
    def _db_matches_latest_commit(self):
        with self.lock:
            latest_commit = read_n_to_last_line(self.commits_fn, n=1)
            if latest_commit:
                _, commit_hash = latest_commit.strip().split(":")
                return commit_hash == sha256_filedigest(self.db_fn)
        return

    @property
    def latest(self):
        with self.lock:
            return self._process_data(read_n_to_last_line(self.trans_fn, n=1))

    def search(self, trans_id: float, include_following: bool = False):
        record = False
        after = []
        with self.lock:
            for line in fileinput.input(self.trans_fn):
                if line.startswith("#commit"):
                    continue
                if not record:
                    if f"{trans_id}:" in line:
                        record = True
                        after.append(self._process_data(line))
                else:
                    if not include_following:
                        break
                    after.append(self._process_data(line))
        return after

    def write(self, trans_id, data):
        with self.lock:
            db_hash = sha256_filedigest(self.db_fn)
            with open(self.trans_fn, "a+") as f:
                f.write(f"{trans_id}:{db_hash}:{data}\n")

    async def commit(self, trans_id):
        from config.database import TinyDB, TINYDB_PARAMS

        with self.lock:
            assert os.path.isfile(f"{self.db_fn}.{trans_id}")
            async with TinyDB(**TINYDB_PARAMS) as db:  # acquires tinydbs lock
                os.rename(f"{self.db_fn}.{trans_id}", self.db_fn)
            with open(self.commits_fn, "a+") as f:
                f.write(f"{trans_id}:{sha256_filedigest(self.db_fn)}\n")


transactions = Transaction()
if not transactions._db_matches_latest_commit:
    logger.error("<transactions> database does not match the latest commit")
    sys.exit(1)


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
        self._failed_peers = set()
        self._established = None

        IN_MEMORY_DB["tasks"] = []

    def _set_master_node(self):
        established = [k for k, v in self.connections.items() if v["meta"]]
        n_online_peers = len(established) + 1
        n_all_peers = len(defaults.CLUSTER_PEERS_THEM) + 1

        current_master_node = self.master_node

        if not (n_online_peers >= (51 / 100) * n_all_peers):
            logger.info("<set_master_node> skipping election, not enough peers")
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
                self.master_node = defaults.CLUSTER_PEERS_ME
                self.role = Role.MASTER

        else:
            their_master = self.connections[master_node]["meta"]["master"]

            if their_master == "ELECTING":
                logger.info(
                    f"<set_master_node> potential master {master_node} is still electing"
                )
                return

            if their_master != master_node:
                logger.warning(
                    f"<set_master_node> not electing {master_node}: node reports different master (are we still joining or changed our swarm size?)"
                )
                return

            if self.master_node != master_node:
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
            f"LTRANS {transactions.latest[0]}",
            "MASTER {master_node}".format(master_node=self.master_node or "ELECTING"),
            f"BIND {defaults.CLUSTER_PEERS_ME}",
            f"HTTP {defaults.HYPERCORN_BIND}",
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
            r"LTRANS (?P<ltrans>\S+)",
            r"MASTER (?P<master>\S+)",
            r"BIND (?P<bind>\S+)",
            r"HTTP (?P<http>\S+)",
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

        if cmd != "INIT":
            self._set_master_node()

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
                if ((ntime_utc_now() - float(ticket)) > 5.0) and not cmd.startswith(
                    "RTASK"
                ):
                    continue

            except asyncio.exceptions.IncompleteReadError:
                async with self.receiving:
                    ticket, receivers = await self.send_command("STATUS", "*")
                    await self._await_receivers(ticket, receivers, raise_on_error=False)
                    break

            try:
                if cmd == "INIT":
                    await self.send_command("ACK", [peer_info["bind"]], ticket=ticket)

                # A task starting with "R" indicates a resync
                elif cmd.startswith("TASK") or cmd.startswith("RTASK"):
                    if (
                        not cmd.startswith("RTASK")
                        and transactions.latest[0] != peer_info["ltrans"]
                    ):
                        await self.send_command(
                            "ACK CRIT:LTRANS_MISMATCH",
                            [peer_info["bind"]],
                            ticket=ticket,
                        )

                    else:
                        try:
                            task_data = TaskModel.parse_raw_task(cmd)
                            init_kwargs, task_kwargs = task_data.kwargs
                            init_kwargs["transaction"] = ticket

                            if task_data.name.startswith("users_"):
                                if task_data.name == "users_create_user":
                                    await Users.create(**init_kwargs).user(
                                        **task_kwargs
                                    )
                                elif task_data.name == "users_create_credential":
                                    await Users.create(**init_kwargs).credential(
                                        **task_kwargs
                                    )
                                elif task_data.name == "users_user_delete":
                                    await Users.user(**init_kwargs).delete()
                                elif task_data.name == "users_user_delete_credential":
                                    await Users.user(**init_kwargs).delete_credential(
                                        **task_kwargs
                                    )
                                elif task_data.name == "users_user_patch":
                                    await Users.user(**init_kwargs).patch(**task_kwargs)
                                elif task_data.name == "users_user_patch_profile":
                                    await Users.user(**init_kwargs).patch_profile(
                                        **task_kwargs
                                    )
                                elif task_data.name == "users_user_patch_credential":
                                    await Users.user(**init_kwargs).patch_credential(
                                        **task_kwargs
                                    )
                            elif task_data.name.startswith("objects_"):
                                if task_data.name == "objects_object_create":
                                    await Objects.object(**init_kwargs).create(
                                        **task_kwargs
                                    )
                                elif task_data.name == "objects_object_patch":
                                    await Objects.object(**init_kwargs).patch(
                                        **task_kwargs
                                    )
                                elif task_data.name == "objects_object_delete":
                                    await Objects.object(**init_kwargs).delete()

                            transactions.write(ticket, cmd)

                            await self.send_command(
                                "ACK", [peer_info["bind"]], ticket=ticket
                            )

                        except Exception as e:
                            logger.error(f"<task> {task_data.name} failed: {e}")
                            await self.send_command(
                                "ACK CRIT:TASK_FAILED",
                                [peer_info["bind"]],
                                ticket=ticket,
                            )

                elif cmd == "COMMIT":
                    await transactions.commit(ticket)
                    await self.send_command("ACK", [peer_info["bind"]], ticket=ticket)

                elif cmd == "STATUS":
                    await self.send_command("ACK", [peer_info["bind"]], ticket=ticket)

                elif cmd == "SYNC":
                    if transactions.latest[0] != peer_info["ltrans"]:
                        if peer_info["ltrans"] > transactions.latest[0]:
                            await self.send_command(
                                "ACK CRIT:SLAVE_MORE_RECENT",
                                [peer_info["bind"]],
                                ticket=ticket,
                            )
                        else:
                            matches = transactions.search(
                                trans_id=peer_info["ltrans"], include_following=True
                            )
                            for t, task in matches[1:]:
                                await self.send_command(
                                    f"R{task}",  # prepend R
                                    [peer_info["bind"]],
                                    ticket=t,
                                )
                            await self.send_command(
                                f"ACK RESYNCED {len(matches[1:])}",
                                [peer_info["bind"]],
                                ticket=ticket,
                            )
                    else:
                        await self.send_command(
                            "ACK LATEST", [peer_info["bind"]], ticket=ticket
                        )

                elif cmd.startswith("FILE"):
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
                    _, _, lock_name = cmd.partition(" ")
                    if lock_name == "":
                        lock_name = "main"

                    self.locks[lock_name].release()
                    await self.send_command("ACK", [peer_info["bind"]], ticket=ticket)

                elif cmd.startswith("LOCK"):
                    _, _, lock_name = cmd.partition(" ")
                    if lock_name == "":
                        lock_name = "main"
                    if not lock_name in self.locks:
                        self.locks[lock_name] = asyncio.Lock()

                    try:
                        await asyncio.wait_for(self.locks[lock_name].acquire(), 0.45)
                    except TimeoutError:
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
            if not peer in self.connections:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                    sock.settimeout(defaults.CLUSTER_PEERS_TIMEOUT)
                    if sock.connect_ex((peer, self.port)) != 0:
                        logger.warning(f"<{peer}> Connection timed out")
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
                    with suppress(KeyError):
                        self._failed_peers.remove(peer)
                except ConnectionRefusedError:
                    if peer not in self._failed_peers:
                        logger.warning(f"<{peer}> ConnectionRefusedError")
                        self._failed_peers.add(peer)

            if self.connections[peer]["streams"]:
                try:
                    await self._send(self.connections[peer]["streams"], ticket, cmd)
                    successful_receivers.append(peer)
                except Exception as e:
                    logger.error(f"<{peer}> disconnected ({type(e)}: {e})")
                    del self.connections[peer]

        return ticket, successful_receivers

    async def release(self, lock_name: str = "") -> str:
        errors = []

        if lock_name == "":
            lock_name = "main"
        if not lock_name in self.locks:
            self.locks[lock_name] = asyncio.Lock()

        if IN_MEMORY_DB["tasks"] and not errors:
            transaction_id = str(CONTEXT_TRANSACTION.get())

            async with self.receiving:
                while IN_MEMORY_DB["tasks"]:
                    task = IN_MEMORY_DB["tasks"].pop()
                    _, receivers = await self.send_command(
                        task, "*", ticket=transaction_id
                    )

                    try:
                        await self._await_receivers(
                            transaction_id, receivers, raise_on_error=True
                        )
                        transactions.write(transaction_id, task)
                    except:
                        errors.append("remote_transaction_failed")
                        break

                if not errors:
                    _, receivers = await self.send_command(
                        "COMMIT", "*", ticket=transaction_id
                    )
                    await self._await_receivers(
                        transaction_id, receivers, raise_on_error=True
                    )
                    await transactions.commit(transaction_id)

        CONTEXT_TRANSACTION.reset(self._context_token)

        if self.role == Role.SLAVE:
            async with self.receiving:
                try:
                    ticket, receivers = await self.send_command(
                        f"UNLOCK {lock_name}", [self.master_node]
                    )
                    ret, responses = await self._await_receivers(
                        ticket, receivers, raise_on_error=True
                    )
                except Exception:
                    errors.append("master_not_reachable")

        with suppress(RuntimeError):
            self.locks[lock_name].release()

        if "remote_transaction_failed" in errors:
            logger.error(
                f"<tasks> a task failed to replicate, not committing transaction"
            )

        if "master_not_reachable" in errors:
            async with self.receiving:
                ticket, receivers = await self.send_command("STATUS", "*")
                await self._await_receivers(ticket, receivers, raise_on_error=False)
            raise DistLockCancelled("Master re-election")

    async def acquire_lock(self, lock_name: str = "") -> str:
        try:
            if lock_name == "":
                lock_name = "main"
            if not lock_name in self.locks:
                self.locks[lock_name] = asyncio.Lock()

            await asyncio.wait_for(self.locks[lock_name].acquire(), 3.0)

        except TimeoutError:
            raise DistLockCancelled("Unable to acquire local lock")

        errors = []
        if self.role == Role.SLAVE:
            async with self.receiving:
                try:
                    ticket, receivers = await self.send_command(
                        f"LOCK {lock_name}", [self.master_node]
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
            self.locks[lock_name].release()
            return await self.acquire_lock(lock_name)

        if "lock_cancelled" in errors:
            self.locks[lock_name].release()
            errors.append("master_not_reachable")

        if "master_not_reachable" in errors:
            self.locks[lock_name].release()
            async with self.receiving:
                ticket, receivers = await self.send_command("STATUS", "*")
                await self._await_receivers(ticket, receivers, raise_on_error=False)
            raise DistLockCancelled("Master re-election")

        IN_MEMORY_DB["tasks"] = []
        self._context_token = CONTEXT_TRANSACTION.set(ntime_utc_now())

    async def request_files(self, files: str | list, peers="*"):
        files = ensure_list(files)
        async with self.receiving:
            try:
                for file in files:
                    if not is_path_within_cwd(file):
                        logger.error(f"<request_files> file not within cwd: {file}")
                        continue

                    ticket, receivers = await self.send_command(f"FILE {file}", peers)
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

        async with self.receiving:
            for cmd in ["INIT", "STATUS"]:
                ticket, receivers = await self.send_command(cmd, "*")
                await self._await_receivers(ticket, receivers, raise_on_error=False)

            try:
                ticket, receivers = await self.send_command("SYNC", [self.master_node])
                _, responses = await self._await_receivers(
                    ticket, receivers, raise_on_error=True
                )
                if responses:
                    logger.success(f"<sync> {responses[0]}")

            except:
                shutdown_trigger.set()
                for p, _ in self.connections.items():
                    r, w = self.connections[p]["streams"]
                    w.close()
                    await w.wait_closed()

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
