import contextvars
import json
import os
import shutil

from config.database import IN_MEMORY_DB, TINYDB_PARAMS
from copy import copy
from functools import wraps
from models.tasks import TaskModel
from pydantic import ValidationError
from typing import Literal
from utils.helpers import is_path_within_cwd


class _BytesJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)


CONTEXT_TRANSACTION = contextvars.ContextVar("context_transaction", default=None)


def evaluate_db_params(kwargs):
    db_params = copy(TINYDB_PARAMS)

    if CONTEXT_TRANSACTION.get():
        transaction_file = f"database/main.{CONTEXT_TRANSACTION.get()}"
    elif kwargs.get("transaction"):
        transaction_file = "database/main.{transaction}".format(
            transaction=float(kwargs.get("transaction"))
        )
    else:
        transaction_file = TINYDB_PARAMS["filename"]

    if transaction_file != TINYDB_PARAMS["filename"]:
        assert is_path_within_cwd(transaction_file)
        if not os.path.exists(transaction_file):
            shutil.copy(TINYDB_PARAMS["filename"], transaction_file)

    db_params["filename"] = transaction_file

    return db_params


def cluster_task(task_name, enforce_uuid: bool = False):
    def form_task(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            if not CONTEXT_TRANSACTION.get():
                return result

            self = args[0] if args else None

            if enforce_uuid:
                self.init_kwargs.update({"_enforce_uuid": result})

            task_request = "TASK {task_name} [{init_kwargs}, {task_kwargs}]".format(
                task_name=task_name,
                init_kwargs=json.dumps(self.init_kwargs, cls=_BytesJSONEncoder),
                task_kwargs=json.dumps(kwargs, cls=_BytesJSONEncoder),
            )

            TaskModel.parse_raw_task(task_request)

            if task_request not in IN_MEMORY_DB["tasks"]:
                IN_MEMORY_DB["tasks"].append(task_request)

            return result

        return wrapper

    return form_task
