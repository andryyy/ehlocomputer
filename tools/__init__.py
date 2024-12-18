import contextvars
import inspect
import json
import os
import shutil

from config.database import IN_MEMORY_DB, QueryInstance, TINYDB_PARAMS
from copy import copy
from functools import wraps
from models.tasks import TaskModel
from pydantic import ValidationError
from quart import current_app, session
from typing import Literal
from utils.helpers import is_path_within_cwd


class _TaskJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, QueryInstance):
            return None
        return super().default(obj)


CONTEXT_TRANSACTION = contextvars.ContextVar("context_transaction", default=None)


def whoami(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if current_app and session.get("id"):
            self.user_id = session["id"]
        func(self, *args, **kwargs)

    return wrapper


def evaluate_db_params():
    db_params = copy(TINYDB_PARAMS)

    if CONTEXT_TRANSACTION.get():
        transaction_file = f"database/main.{CONTEXT_TRANSACTION.get()}"
    else:
        transaction_file = "database/main"

    if transaction_file != "database/main":
        assert is_path_within_cwd(transaction_file)
        if not os.path.exists(transaction_file):
            shutil.copy(f"database/main", transaction_file)

    db_params["filename"] = transaction_file

    return db_params


def cluster_task(task_name, enforce_uuid: bool = False):
    def form_task(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            result = await func(self, *args, **kwargs)

            if enforce_uuid:
                self.uuid = result

            task_request = "TASK {task_name} [{init_kwargs}, {task_kwargs}]".format(
                task_name=task_name,
                init_kwargs=json.dumps(vars(self), cls=_TaskJSONEncoder),
                task_kwargs=json.dumps(kwargs, cls=_TaskJSONEncoder),
            )

            TaskModel.parse_raw_task(task_request)

            if task_request not in IN_MEMORY_DB["tasks"]:
                IN_MEMORY_DB["tasks"].append(task_request)

            return result

        return wrapper

    return form_task
