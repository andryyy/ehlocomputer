import asyncio
import binascii
import json
import models.auth as auth_model
import models.users as users_model
import re

from config import *
from models.tasks import TaskModel
from pydantic import AfterValidator, Field, ValidationError, constr, validate_call
from typing import Annotated, Awaitable, Callable
from utils.helpers import ensure_list
from uuid import UUID

IN_MEMORY_DB["user_tasks"] = []
IN_MEMORY_DB["failed_user_tasks"] = []


class _BytesJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            # Convert bytes to a hexadecimal string
            return obj.hex()
        # For other types, use the default method
        return super().default(obj)


async def users_contextmanager_enter(
    self, call_after_lock: Awaitable | Callable | None = None
):
    if self.cluster:
        await self.cluster.acquire_lock()
    else:
        logger.info("No cluster instance provided, saving locally only")
    if isinstance(call_after_lock, Callable):
        call_after_lock
    if isinstance(call_after_lock, Awaitable):
        await call_after_lock
    return self


async def users_contextmanager_exit(self, exc_type, exc_value, exc_tb):
    if self.cluster:
        try:
            failed_tasks = await self.cluster.add_tasks(IN_MEMORY_DB["user_tasks"])
            IN_MEMORY_DB["user_tasks"] = []
            IN_MEMORY_DB["failed_user_tasks"] += list(failed_tasks)
            if failed_tasks:
                raise Exception(
                    "Some tasks could not be processed and remain in the queue"
                )
        finally:
            await self.cluster.release()
    else:
        IN_MEMORY_DB["user_tasks"] = []


def users__create_task(func):
    async def wrapper(self, *args, **kwargs):
        task = f"users_{self.__class__.__name__.lower()}"
        func_name = func.__name__.lower()
        if func_name != "__call__":
            task += f"_{func_name}"

        result = await func(self, *args, **kwargs)

        try:
            task_request = "TASK {task} [{init_data}, {payload}]".format(
                task=task,
                init_data=json.dumps({"_enforce_uuid": result}),
                payload=json.dumps(kwargs, cls=_BytesJSONEncoder),
            )
            TaskModel.parse_raw_task(task_request)
        except (ValidationError, ValueError) as e:
            print("Task validation error:", e)

        if task_request not in IN_MEMORY_DB["user_tasks"]:
            IN_MEMORY_DB["user_tasks"].append(task_request)

        return result

    return wrapper


def users__user_task(func):
    async def wrapper(self, *args, **kwargs):
        task = f"user_{self.__class__.__name__.lower()}"
        func_name = func.__name__.lower()
        if func_name != "__call__":
            task += f"_{func_name}"

        result = await func(self, *args, **kwargs)

        matched_attr = self._user_class._matched_attr
        user_init = {
            matched_attr: getattr(self._user_class, matched_attr),
        }

        try:
            task_request = f"TASK {task} [{json.dumps(user_init, cls=_BytesJSONEncoder)}, {json.dumps(kwargs, cls=_BytesJSONEncoder)}]"
            TaskModel.parse_raw_task(task_request)
        except (ValidationError, ValueError) as e:
            print("Task validation error:", e)

        if task_request not in IN_MEMORY_DB["user_tasks"]:
            IN_MEMORY_DB["user_tasks"].append(task_request)

        return result

    return wrapper


def _create_credentials_mapping(credentials: dict):
    user_credentials = dict()
    for c in credentials:
        user_credentials.update({c["id"]: auth_model.CredentialRead.parse_obj(c)})
    return user_credentials


class Users:
    def __init__(self):
        pass

    class create:
        def __init__(self, *args, **kwargs):
            self.cluster = kwargs.get("cluster")
            self._enforce_uuid = kwargs.get("_enforce_uuid")

        async def __aenter__(self):
            return await users_contextmanager_enter(self)

        async def __aexit__(self, exc_type, exc_value, exc_tb):
            return await users_contextmanager_exit(self, exc_type, exc_value, exc_tb)

        @users__create_task
        async def __call__(self, data: dict):
            validated_data = users_model.UserAdd.parse_obj(data).dict()

            if self._enforce_uuid:
                validated_data["id"] = self._enforce_uuid

            async with TinyDB(**TINYDB_PARAMS) as db:
                name_conflict = db.table("users").search(
                    Query().login == validated_data["login"]
                )
                if name_conflict:
                    raise ValueError("name", "The provided login name exists")
                db.table("users").insert(validated_data)

            return validated_data["id"]

        @users__create_task
        async def credential(self, data: dict, assign_user_id: str | None = None):
            validated_data = auth_model.AddCredential.parse_obj(data).dict()

            async with TinyDB(**TINYDB_PARAMS) as db:
                if assign_user_id:
                    user = db.table("users").get(Query().id == assign_user_id)
                    if not user:
                        raise ValueError(
                            "name",
                            "The provided user ID for auto assignment does not exist, credential was not created",
                        )

                db.table("credentials").insert(validated_data)

                if assign_user_id:
                    user["credentials"].append(validated_data["id"])
                    db.table("users").update(
                        {"credentials": user["credentials"]},
                        Query().id == assign_user_id,
                    )

            return validated_data["id"]

    class user:
        def __init__(self, *args, **kwargs):
            users_attr = users_model._Users_attr.parse_obj(kwargs)

            self.cluster = kwargs.get("cluster")

            # Base attributes
            self.id = users_attr.id
            self.login = users_attr.login

            self._matched_attr = users_attr.matched_attr
            self._query_filter = getattr(Query(), users_attr.matched_attr) == getattr(
                self, users_attr.matched_attr
            )

            # Sub classes
            self.patch = self.Patch(self)
            self.delete = self.Delete(self)

            self._user_data = None  # to be set on aenter or refresh function

        async def __aenter__(self):
            return await users_contextmanager_enter(self, self.refresh())

        async def __aexit__(self, exc_type, exc_value, exc_tb):
            return await users_contextmanager_exit(self, exc_type, exc_value, exc_tb)

        def get(self):
            return self._user_data

        async def refresh(self) -> None:
            async with TinyDB(**TINYDB_PARAMS) as db:
                user = users_model.User.parse_obj(
                    db.table("users").get(self._query_filter)
                )
                credentials = db.table("credentials").search(
                    (Query().id.one_of(user.credentials))
                )
                user.credentials = _create_credentials_mapping(credentials)
                self._user_data = user

        class Delete:
            def __init__(self, user_class):
                self._user_class = user_class
                self._query_filter = user_class._query_filter

            @users__user_task
            async def __call__(self):
                async with TinyDB(**TINYDB_PARAMS) as db:
                    user = db.table("users").get(self._query_filter)
                    for credential_hex_id in user["credentials"]:
                        db.table("credentials").remove(Query().id == credential_hex_id)
                    deleted = db.table("users").remove(self._query_filter)
                    return user["id"]

            @users__user_task
            @validate_call
            async def credential(
                self, hex_id: constr(pattern=r"^[0-9a-fA-F]+$", min_length=2)
            ):
                async with TinyDB(**TINYDB_PARAMS) as db:
                    user = db.table("users").get(self._query_filter)
                    if hex_id in user["credentials"]:
                        del user["credentials"][hex_id]
                        db.table("credentials").remove(Query().id == hex_id)
                        db.table("users").update(
                            {"credentials": user["credentials"]},
                            self._query_filter,
                        )
                        return hex_id

        class Patch:
            def __init__(self, user_class):
                self._user_class = user_class
                self._query_filter = user_class._query_filter

            @users__user_task
            async def __call__(self, data: dict):
                validated_data = users_model.UserPatch.parse_obj(data)
                async with TinyDB(**TINYDB_PARAMS) as db:
                    name_conflict = db.table("users").search(
                        (Query().login == validated_data.login)
                        & (~(self._query_filter))
                    )
                    if name_conflict:
                        raise ValueError("login", "The provided login name exists")

                    user = db.table("users").get(self._query_filter)
                    orphaned_credentials = [
                        c
                        for c in user["credentials"]
                        if c not in validated_data.credentials
                    ]
                    db.table("users").update(
                        validated_data.dict(exclude_none=True),
                        self._query_filter,
                    )
                    db.table("credentials").remove(
                        Query().id.one_of(orphaned_credentials)
                    )
                    return user["id"]

            @users__user_task
            async def profile(self, data: dict):
                validated_data = users_model.UserProfile.parse_obj(data).dict(
                    exclude_none=True
                )
                async with TinyDB(**TINYDB_PARAMS) as db:
                    user = db.table("users").get(self._query_filter)
                    patched = db.table("users").update(
                        {"profile": user["profile"] | validated_data},
                        self._query_filter,
                    )
                    return user["id"]

            @users__user_task
            async def credential(
                self,
                hex_id: constr(pattern=r"^[0-9a-fA-F]+$", min_length=2),
                data: dict,
            ):
                validated_data = auth_model.CredentialPatch.parse_obj(data)
                async with TinyDB(**TINYDB_PARAMS) as db:
                    user = db.table("users").get(self._query_filter)
                    if hex_id not in user["credentials"]:
                        raise ValueError(
                            "hex_id",
                            "The provided credential ID was not found in user context",
                        )
                    db.table("credentials").update(
                        validated_data.dict(exclude_none=True), Query().id == hex_id
                    )

                    return hex_id

    async def exists(
        self, id: str | list | None = None, login: str | list | None = None
    ) -> bool:
        attr = users_model._Users_attr(id=id, login=login)
        ids = ensure_list(attr.id)
        logins = ensure_list(attr.login)

        async with TinyDB(**TINYDB_PARAMS) as db:
            matches = db.table("users").search(
                Query().id.one_of(ids) if ids else Query().login.one_of(logins)
            )
            if ids:
                return set([m["id"] for m in matches]) == set(ids)
            return set([m["login"] for m in matches]) == set(login)

    @validate_call
    async def search(self, q: constr(strip_whitespace=True, min_length=0) = Field(...)):
        in_q = lambda s: q in s
        async with TinyDB(**TINYDB_PARAMS) as db:
            matches = db.table("users").search(
                (Query().login.test(in_q)) | (Query().id.test(in_q))
            )

            _parsed = []
            for user in matches:
                user = users_model.User.parse_obj(user)
                credentials = db.table("credentials").search(
                    Query().id.one_of(user.credentials)
                )
                user.credentials = _create_credentials_mapping(credentials)
                _parsed.append(user)

        return _parsed

    @validate_call
    async def search_credential(
        self, q: constr(strip_whitespace=True, min_length=0) = Field(...)
    ):
        in_q = lambda s: q in s
        async with TinyDB(**TINYDB_PARAMS) as db:
            matches = db.table("credentials").search(
                (Query().id.test(in_q)) | (Query().friendly_name.test(in_q))
            )
            return _create_credentials_mapping(matches)
