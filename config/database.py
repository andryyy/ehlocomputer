import json
import redis
import time

from . import logger
from datetime import datetime, timezone
from jsondiff import diff
from pathlib import Path
from tinydb import Query, TinyDB
from tinydb.middlewares import Middleware
from tinydb.storages import JSONStorage
from uuid import uuid4

__all__ = ["r", "TinyDB", "Query", "RedisLockMiddleware"]

r = redis.Redis(host="localhost", port=6379, protocol=3, decode_responses=True)


# Only a single operation is allowed for now. TODO: FIXME
class RedisLockMiddleware(Middleware):
    def __init__(self, storage_cls):
        # Any middleware *has* to call the super constructor
        # with storage_cls
        super().__init__(storage_cls)  # (1)

    def read(self):
        read_ticket = f"fileread:{str(uuid4())}"
        r.xadd(
            "ehlotalk",
            {
                "command": "fileread",
                "filename": self._handle.name,
                "ticket": read_ticket,
            },
        )

        data_read = r.get(read_ticket)
        _await_start = time.time()
        while not data_read:
            if time.time() - _await_start > 1.5:
                logger.error("Timeout reading from cache")
                raise TimeoutError
            data_read = r.get(read_ticket)

        return json.loads(data_read)

    def write(self, data):
        serialized = json.dumps(data, **self.kwargs)
        r.xadd(
            "ehlotalk",
            {
                "command": "filewrite",
                "filename": self._handle.name,
                "data": serialized,
            },
        )
