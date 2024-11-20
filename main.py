import asyncio
import signal
import ssl
import sys

from config import defaults
from config.cluster import cluster
from hypercorn.asyncio import serve
from hypercorn.config import Config
from hypercorn.middleware import ProxyFixMiddleware
from web import app

hypercorn_config = Config()
hypercorn_config.bind = [defaults.HYPERCORN_BIND]
hypercorn_config.certfile = defaults.TLS_CERTFILE
hypercorn_config.keyfile = defaults.TLS_KEYFILE
hypercorn_config.include_server_header = False
hypercorn_config.server_names = defaults.HOSTNAME
hypercorn_config.ciphers = "ECDHE+AESGCM"
hypercorn_shutdown_event = asyncio.Event()


def _signal_handler(*_) -> None:
    hypercorn_shutdown_event.set()


async def main():
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGTERM, _signal_handler)

    def _exception_handler(loop, context):
        exception = context.get("exception")
        if isinstance(exception, ssl.SSLError) or isinstance(
            exception, asyncio.sslproto._SSLProtocolTransport
        ):
            pass
        elif isinstance(exception, OSError) and exception.errno == 99:
            hypercorn_shutdown_event.set()
            sys.exit(0)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(_exception_handler)

    async with asyncio.TaskGroup() as group:
        asyncio.create_task(
            serve(
                ProxyFixMiddleware(app, mode="legacy", trusted_hops=1),
                hypercorn_config,
                shutdown_trigger=hypercorn_shutdown_event.wait,
            ),
            name="qrt",
        ),
        asyncio.create_task(
            cluster.run(shutdown_trigger=hypercorn_shutdown_event),
            name="cluster",
        ),
        await hypercorn_shutdown_event.wait()


asyncio.run(main())
