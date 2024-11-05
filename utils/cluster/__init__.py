import asyncio
import json
import random
import re
import ssl

from config.database import IN_MEMORY_DB
from config import defaults
from config.logs import logger
from contextlib import suppress
from enum import Enum
from tools import IN_CLUSTER_CONTEXT, CLUSTER_TASKS
from tools.users import Users
from tools.objects import Objects
from utils.datetimes import ntime_utc_now
from utils.helpers import ensure_list
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


class Role(Enum):
    MASTER = 1
    SLAVE = 0


class Cluster:
    def __init__(self, host, port):
        assert isinstance(host, str) or isinstance(host, list)
        assert isinstance(defaults.CLUSTER_CLI_BINDINGS, list)

        self.connections = dict()
        self.host = ensure_list(host) + defaults.CLUSTER_CLI_BINDINGS
        self.lock = asyncio.Lock()
        self.master_node = None
        self.port = port
        self.receiving = asyncio.Condition()
        self.role = Role.SLAVE
        self.started = ntime_utc_now()
        self.tickets = dict()

        self._failed_peers = set()

        IN_MEMORY_DB["tasks"] = []
        IN_MEMORY_DB["failed_tasks"] = []

    def set_master_node(self):
        established = [k for k, v in self.connections.items() if v["meta"]]
        online_peers = len(established) + 1
        all_peers = len(defaults.CLUSTER_PEERS_THEM) + 1
        current_master_node = self.master_node

        if not (online_peers >= (51 / 100) * all_peers):
            logger.info("<set_master_node> Skipping election, not enough peers")
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

        if self.started < started:
            self.master_node = defaults.CLUSTER_PEERS_ME
            self.role = Role.MASTER
        else:
            self.master_node = master_node
            self.role = Role.SLAVE

        if current_master_node != self.master_node:
            logger.info(f"<set_master_node> Elected {self.master_node} as master")

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

        self.set_master_node()

        self.log_rx(
            "{bind}[{node}]".format(bind=meta_dict["bind"], node=meta_dict["name"]),
            f"Ticket {ticket}, Command {cmd}",
        )

        return ticket, cmd, meta_dict

    async def _task_processor(self, tasks: list):
        async with self.receiving:
            failed_tasks = set()
            for task in tasks:
                ticket, receivers = await self.send_command(task, "*")
                try:
                    await self._await_receivers(ticket, receivers, raise_on_error=True)
                except:
                    failed_tasks.add(task)
            return list(failed_tasks)

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
                if (ntime_utc_now() - float(ticket)) > 5.0:
                    continue
            except asyncio.exceptions.IncompleteReadError:
                async with self.receiving:
                    ticket, receivers = await self.send_command("STATUS", "*")
                    await self._await_receivers(ticket, receivers, raise_on_error=False)
                    break

            try:
                if cmd.startswith("TASK"):
                    _, _, payload = cmd.partition(" ")
                    task_type, _, combined_data = payload.partition(" ")

                    if task_type not in CLUSTER_TASKS:
                        await self.send_command(
                            "ACK CRIT", [peer_info["bind"]], ticket=ticket
                        )
                    else:
                        try:
                            init_kwargs, task_kwargs = json.loads(combined_data)
                            if task_type.startswith("users_"):
                                if task_type == "users_create_user":
                                    await Users.create(**init_kwargs).user(
                                        **task_kwargs
                                    )
                                elif task_type == "users_create_credential":
                                    await Users.create(**init_kwargs).credential(
                                        **task_kwargs
                                    )
                                elif task_type == "users_user_delete":
                                    await Users.user(**init_kwargs).delete()
                                elif task_type == "users_user_delete_credential":
                                    await Users.user(**init_kwargs).delete_credential(
                                        **task_kwargs
                                    )
                                elif task_type == "users_user_patch":
                                    await Users.user(**init_kwargs).patch(**task_kwargs)
                                elif task_type == "users_user_patch_profile":
                                    await Users.user(**init_kwargs).patch_profile(
                                        **task_kwargs
                                    )
                                elif task_type == "users_user_patch_credential":
                                    await Users.user(**init_kwargs).patch_credential(
                                        **task_kwargs
                                    )
                            elif task_type.startswith("objects_"):
                                if task_type == "objects_object_create":
                                    await Objects.object(**init_kwargs).create(
                                        **task_kwargs
                                    )
                                elif task_type == "objects_object_patch":
                                    await Objects.object(**init_kwargs).patch(
                                        **task_kwargs
                                    )
                                elif task_type == "objects_object_delete":
                                    await Objects.object(**init_kwargs).delete()
                            await self.send_command(
                                "ACK", [peer_info["bind"]], ticket=ticket
                            )
                        except Exception as e:
                            logger.error(f"<task> {task_type} failed: {e}")

                elif cmd == "STATUS":
                    await self.send_command("ACK", [peer_info["bind"]], ticket=ticket)

                elif cmd == "UNLOCK":
                    self.lock.release()
                    await self.send_command("ACK", [peer_info["bind"]], ticket=ticket)

                elif cmd == "LOCK":
                    try:
                        await asyncio.wait_for(self.lock.acquire(), 0.45)
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
                    logger.error(f"<{peer}> disconnected ({type(e)})")
                    del self.connections[peer]

        return ticket, successful_receivers

    async def release(self) -> str:
        errors = []

        if self.role == Role.SLAVE:
            async with self.receiving:
                try:
                    ticket, receivers = await self.send_command(
                        "UNLOCK", [self.master_node]
                    )
                    ret, responses = await self._await_receivers(
                        ticket, receivers, raise_on_error=True
                    )
                except Exception:
                    errors.append("master_not_reachable")

        with suppress(RuntimeError):
            self.lock.release()

        if "master_not_reachable" in errors:
            async with self.receiving:
                ticket, receivers = await self.send_command("STATUS", "*")
                await self._await_receivers(ticket, receivers, raise_on_error=False)
            raise DistLockCancelled("Master re-election")

    async def __aenter__(self):
        IN_MEMORY_DB["tasks"] = []
        await self.acquire_lock()
        self.token = IN_CLUSTER_CONTEXT.set(ntime_utc_now())

    async def __aexit__(self, exc_type, exc_value, exc_tb):
        try:
            failed_tasks = await self._task_processor(IN_MEMORY_DB["tasks"])
            IN_MEMORY_DB["tasks"] = []
            if failed_tasks:
                IN_MEMORY_DB["failed_tasks"] += failed_tasks
                print("retrying some failed tasks:")
                print(IN_MEMORY_DB["failed_tasks"])
        except:
            print("err")

        print({"filename": f"database/main.{IN_CLUSTER_CONTEXT.get()}"})

        IN_CLUSTER_CONTEXT.reset(self.token)
        await self.release()

    async def acquire_lock(self) -> str:
        try:
            await asyncio.wait_for(self.lock.acquire(), 3.0)
        except TimeoutError:
            raise DistLockCancelled("Unable to acquire local lock")

        errors = []
        if self.role == Role.SLAVE:
            async with self.receiving:
                try:
                    ticket, receivers = await self.send_command(
                        "LOCK", [self.master_node]
                    )
                    result, responses = await self._await_receivers(
                        ticket, receivers, raise_on_error=True
                    )
                    if "BUSY" in responses:
                        errors.append("master_busy")
                except asyncio.CancelledError:
                    errors.append("lock_cancelled")
                except Exception:
                    errors.append("master_not_reachable")

        if "master_busy" in errors:
            self.lock.release()
            return await self.acquire_lock()

        if "lock_cancelled" in errors:
            errors.append("master_not_reachable")

        if "master_not_reachable" in errors:
            self.lock.release()
            async with self.receiving:
                ticket, receivers = await self.send_command("STATUS", "*")
                await self._await_receivers(ticket, receivers, raise_on_error=False)
            raise DistLockCancelled("Master re-election")

    async def run(self) -> None:
        server = await asyncio.start_server(
            self.connection_handler,
            self.host,
            self.port,
            ssl=get_ssl_context("server"),
            limit=10485760,  # 10 MiB
        )

        logger.info(f"Listening on {self.port} on address {" and ".join(self.host)}...")

        async with self.receiving:
            ticket, receivers = await self.send_command("STATUS", "*")
            await self._await_receivers(ticket, receivers, raise_on_error=False)

        async with server:
            await server.serve_forever()

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

            if len(responses) != len(receivers):
                _err_msg = "unplausible amount of responses for ticket"

            if "CRIT" in responses:
                _err_msg = "one or more peers reported CRIT"

            del self.tickets[ticket]

            if _err_msg:
                if raise_on_error:
                    raise IncompleteClusterResponses(f"<{ticket}> {_err_msg}")
                logger.error(_err_msg)
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

                if cmd == b"\x98":
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
