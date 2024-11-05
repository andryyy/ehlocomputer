import contextvars
import json

from config.database import IN_MEMORY_DB
from functools import wraps
from models.tasks import TaskModel
from pydantic import ValidationError
from typing import Literal

IN_CLUSTER_CONTEXT = contextvars.ContextVar("cluster_context", default=False)


class _BytesJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)


CLUSTER_TASKS = [
    "users_create_user",
    "users_create_credential",
    "users_user_patch",
    "users_user_patch_profile",
    "users_user_patch_credential",
    "users_user_delete",
    "users_user_delete_credential",
    "objects_object_create",
    "objects_object_patch",
    "objects_object_delete",
]


def cluster_task(task_name, enforce_uuid: bool = False):
    def form_task(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            if not IN_CLUSTER_CONTEXT.get():
                return result

            self = args[0] if args else None

            try:
                if enforce_uuid:
                    self.init_kwargs.update({"_enforce_uuid": result})

                task_request = "TASK {task_name} [{init_kwargs}, {task_kwargs}]".format(
                    task_name=task_name,
                    init_kwargs=json.dumps(self.init_kwargs, cls=_BytesJSONEncoder),
                    task_kwargs=json.dumps(kwargs, cls=_BytesJSONEncoder),
                )
                TaskModel.parse_raw_task(task_request)
            except (ValidationError, ValueError) as e:
                print("Task validation error:", e)

            if task_request not in IN_MEMORY_DB["tasks"]:
                IN_MEMORY_DB["tasks"].append(task_request)

            return result

        return wrapper

    return form_task
