import asyncio
import signal
import ssl
import sys

from components.cluster.cluster import cluster
from hypercorn.asyncio import serve
from hypercorn.config import Config
from hypercorn.middleware import ProxyFixMiddleware
from components.web import *

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
            print("ERROR: Unable to bind to an address")
            hypercorn_shutdown_event.set()
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
        try:
            await hypercorn_shutdown_event.wait()
        except asyncio.CancelledError:
            hypercorn_shutdown_event.set()
        finally:
            print("Shutting down")
            sys.exit(0)


asyncio.run(main())
