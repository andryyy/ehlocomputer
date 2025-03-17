import contextvars
import os
import shutil
import json

from aiotinydb import AIOTinyDB as TinyDB
from aiotinydb.storage import AIOStorage
from copy import copy
from tinydb import Query
from tinydb.table import Document
from components.utils import is_path_within_cwd

__all__ = [
    "TinyDB",
    "Query",
    "Document",
    "TINYDB_PARAMS",
    "IN_MEMORY_DB",
    "CTX_TICKET",
    "evaluate_db_params",
    "dbcommit",
]

TinyDB.DEFAULT_TABLE_KWARGS = {"cache_size": 0}
TINYDB_PARAMS = {
    "filename": "database/main",
    "indent": 2,
    "sort_keys": True,
}
IN_MEMORY_DB = dict()
CTX_TICKET = contextvars.ContextVar("CTX_TICKET", default=None)


def evaluate_db_params(ticket: str | None = None):
    db_params = copy(TINYDB_PARAMS)
    transaction_file = (
        f"database/main.{ticket}"
        if ticket
        else f"database/main.{CTX_TICKET.get() or ''}".rstrip(".")
    )

    if transaction_file != "database/main" and is_path_within_cwd(transaction_file):
        if not os.path.exists(transaction_file):
            shutil.copy("database/main", transaction_file)

    db_params["filename"] = transaction_file
    return db_params


async def dbcommit(commit_tables: set, ticket: str | None = None) -> None:
    assert commit_tables
    db_params = evaluate_db_params(ticket)

    with open(db_params["filename"], "r") as f:
        modified_db = json.load(f)

    async with TinyDB(**TINYDB_PARAMS) as db:
        current_db = json.load(db._storage._handle)
        for t in commit_tables:
            current_db[t] = modified_db[t]
        db._storage._handle.seek(0)
        serialized = json.dumps(current_db, **db._storage.kwargs)
        db._storage._handle.write(serialized)
        db._storage._handle.flush()
        db._storage._handle.truncate()
        os.unlink(db_params["filename"])
