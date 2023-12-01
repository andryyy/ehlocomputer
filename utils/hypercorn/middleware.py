from config import defaults, logger
from hypercorn.typing import ASGIFramework, HTTPScope, Scope, WWWScope, WebsocketScope
from typing import Callable


class ReadTrustedProxyHeaders:
    def __init__(self, app: ASGIFramework):
        self.app = app
        self.trusted_proxies = defaults.TRUSTED_PROXIES

    async def __call__(self, scope: Scope, receive: Callable, send: Callable) -> None:
        if scope["type"] == "http":
            client_addr = scope["client"][0]
            proxy_headers = {
                header[0].decode("ascii"): header[1].decode("ascii")
                for header in scope["headers"]
                if header[0].decode("ascii")
                in [
                    "x-forwarded-proto",
                    "x-forwarded-for",
                    "x-real-ip",
                ]
            }
            if client_addr in self.trusted_proxies:
                logger.debug(f"{client_addr} is a trusted proxy")
                scope["client"] = (
                    proxy_headers.get("x-forwarded-for"),
                    scope["client"][1],
                )
                scope["scheme"] = proxy_headers.get("x-forwarded-proto")
                return await self.app(scope, receive, send)
        else:
            return await self.app(scope, receive, send)
