import aiohttp
import asyncio
import html
import json
import socket
import time
import uuid

from config import defaults, logger
from config.database import *
from functools import partial
from podman import PodmanClient
from pydantic import AfterValidator, validate_call
from pydantic.networks import IPv4Address, IPv6Address
from quart import session
from typing import Annotated, Literal


@validate_call
def get_listener_by_id(
    listener_id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))],
    realm_path: str,
):
    with TinyDB(**defaults.TINYDB, path=realm_path) as db:
        listener_table = db.table("listeners")
        return listener_table.get(Query().id == listener_id)


@validate_call
def get_listener_by_name(name: str, realm_path: str):
    with TinyDB(**defaults.TINYDB, path=realm_path) as db:
        listener_table = db.table("listeners")
        return listener_table.get(Query().name == name)


@validate_call
def is_port_bindable(ip: IPv4Address | IPv6Address, port):
    af = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    with socket.socket(af, socket.SOCK_STREAM) as s:
        try:
            s.bind((ip.__str__(), port))
            return True
        except OSError as e:
            return False


@validate_call
def get_container_name(
    listener_id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))],
    worker: str,
    podman_socket: str,
):
    with PodmanClient(base_url=f"unix://{podman_socket}") as client:
        containers = client.containers.list(
            all=True,
            filters=[
                f"label=listener_id={listener_id}",
                f"label=worker={worker}",
            ],
        )
        if len(containers) == 1:
            container = containers.pop()
            return container.name


class Stream:
    @validate_call
    def __init__(
        self,
        listener_id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))],
        worker: str,
        stream_id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))],
        podman_socket,
    ):
        global r
        self.r = r
        self.user_login = session.get("login")
        self.listener_id = listener_id
        self.worker = worker
        self.stream_id = stream_id
        self.podman_socket = podman_socket
        self.container_name = get_container_name(
            listener_id, worker, self.podman_socket
        )
        self.r.set(f"stream:{session.get('login')}", stream_id, ex=300)

    async def run(self):
        log_stream = asyncio.create_task(self._log_stream_generator())
        await asyncio.create_task(self._validate_session())
        log_stream.cancel()

    @validate_call
    def _stream_parser(self, data: bytes):
        header = data[:8]

        stream_type = int.from_bytes(header[0:1])
        frame_length = int.from_bytes(header[4:8], "big")

        std = "STDOUT" if stream_type == 1 else "STDERR"
        data = (
            data[8 : frame_length + 8]
            .decode("utf-8", errors="ignore")
            .lstrip()
            .rstrip()
        )

        return std, data

    @validate_call
    async def _validate_session(self):
        while True:
            # This is not a duplicate of a similar check in _log_stream_generator
            # This loop will only verify the stream id but not prolong the corresponding Redis key
            active_stream = self.r.get(f"stream:{self.user_login}")
            if active_stream != self.stream_id:
                logger.warning(f"Stream is {self.stream_id} for {active_stream}")
                break
            await asyncio.sleep(1)

    @validate_call
    async def _log_stream_generator(self, tail: str = "20"):
        stream_session = aiohttp.ClientSession(
            connector=aiohttp.UnixConnector(path=self.podman_socket)
        )
        client_session = aiohttp.ClientSession()
        nchan_post = partial(
            client_session.post, f"http://127.0.0.1:8555/pub/user/{self.user_login}"
        )

        while True:
            try:
                # This check ensures the stream key still exists and matches the instance's session id
                # If it exists, its TTL will be prolonged by 300s
                active_stream = self.r.getex(f"stream:{self.user_login}", ex=300)
                if active_stream != self.stream_id:
                    logger.warning(
                        f"Stream mismatch, closing {self.stream_id} for {active_stream}"
                    )
                    break

                # The stream must timeout after the stream:<user> key
                # On timeout the loop continues and retries to fetch the key which then should already be vanished
                async with stream_session.get(
                    f"http://localhost/containers/{self.container_name}/logs",
                    params={"stderr": 1, "stdout": 1, "follow": 1, "tail": tail},
                    timeout=310,
                ) as response:
                    async for data, _ in response.content.iter_chunks():
                        std, message = self._stream_parser(data)
                        await nchan_post(
                            json={
                                "iam": "stream",
                                "id": self.stream_id,
                                "std": std,
                                "message": html.escape(message, quote=True),
                            }
                        )

                with PodmanClient(base_url=f"unix://{self.podman_socket}") as client:
                    if client.containers.exists(self.container_name):
                        data = client.containers.get(self.container_name).attrs["State"]
                        await nchan_post(
                            json={
                                "iam": "stream",
                                "id": self.stream_id,
                                "std": "INFO",
                                "message": html.escape(
                                    f"Stream closed (status: {data['Status']}, exit code: {data['ExitCode']})",
                                    quote=True,
                                ),
                            }
                        )

                        _ok_exit = f"trigger terminalNormalExit on #terminal-container"
                        _nok_exit = f"trigger terminalAbnormalExit(code:{data['ExitCode']}) on #terminal-container"
                        await nchan_post(
                            json={
                                "iam": "_hs",
                                "script": _nok_exit
                                if data["ExitCode"] != 0
                                else _ok_exit,
                            }
                        )

                break

            except asyncio.TimeoutError:
                with PodmanClient(base_url=f"unix://{self.podman_socket}") as client:
                    if client.containers.exists(self.container_name):
                        data = client.containers.get(self.container_name).attrs["State"]
                        if data and data["Status"] in ["running", "starting"]:
                            tail = "0"
                            continue
                            await nchan_post(
                                json={
                                    "iam": "stream",
                                    "id": self.stream_id,
                                    "std": "INFO",
                                    "message": html.escape(
                                        f"Stream closed (status: {data['Status']}, exit code: {data['ExitCode']})",
                                        quote=True,
                                    ),
                                }
                            )
            except asyncio.CancelledError:
                break

        await nchan_post(
            json={
                "iam": "stream",
                "id": self.stream_id,
                "std": "INFO",
                "message": html.escape(f"Stream disconnected", quote=True),
            }
        )
        logger.success(f"Stream {self.stream_id} was stopped")
        await client_session.close()
        await stream_session.close()
