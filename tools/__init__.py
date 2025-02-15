import contextvars
import os
import shutil

from config.database import TINYDB_PARAMS
from copy import copy
from utils.helpers import is_path_within_cwd


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
