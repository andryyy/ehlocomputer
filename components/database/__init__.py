import contextvars
import os
import shutil
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
    "CONTEXT_TRANSACTION",
    "evaluate_db_params",
]

TinyDB.DEFAULT_TABLE_KWARGS = {"cache_size": 0}
TINYDB_PARAMS = {
    "filename": "database/main",
    "indent": 2,
    "sort_keys": True,
}
IN_MEMORY_DB = dict()
CONTEXT_TRANSACTION = contextvars.ContextVar("context_transaction", default=None)


def evaluate_db_params(ticket: str | None = None):
    db_params = copy(TINYDB_PARAMS)
    transaction_file = (
        f"database/main.{ticket}"
        if ticket
        else f"database/main.{CONTEXT_TRANSACTION.get() or ''}".rstrip(".")
    )

    if transaction_file != "database/main" and is_path_within_cwd(transaction_file):
        if not os.path.exists(transaction_file):
            shutil.copy("database/main", transaction_file)

    db_params["filename"] = transaction_file
    return db_params
