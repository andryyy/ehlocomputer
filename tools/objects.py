import asyncio
import json
import models.objects as objects_model
from models.tasks import TaskModel
import re

from config import *
from pydantic import AfterValidator, Field, constr, validate_call, ValidationError
from typing import Annotated, Literal
from utils.helpers import ensure_list
from uuid import UUID

defaults.IN_MEMORY_DB["objects_tasks"] = []
defaults.IN_MEMORY_DB["failed_objects_tasks"] = []


def object_task(func):
    async def wrapper(self, *args, **kwargs):
        task = self.__class__.__name__.lower()
        func_name = func.__name__.lower()
        if func_name != "__call__":
            task += f"_{func_name}"

        result = await func(self, *args, **kwargs)

        object_init = {
            "id": self.id,
            "object_type": self.object_type,
            "_enfore_uuid": result if "create" in func_name else None,
        }

        try:
            task_request = (
                f"TASK {task} [{json.dumps(object_init)}, {json.dumps(kwargs)}]"
            )
            TaskModel.parse_raw_task(task_request)
        except (ValidationError, ValueError) as e:
            print("Task validation error:", e)

        if task_request not in defaults.IN_MEMORY_DB["objects_tasks"]:
            defaults.IN_MEMORY_DB["objects_tasks"].append(task_request)

        return result

    return wrapper


class Objects:
    def __init__(self):
        pass

    class object:
        def __init__(self, *args, **kwargs):
            objects_attr = objects_model._Objects_attr.parse_obj(kwargs)
            self._enfore_uuid = kwargs.get("_enfore_uuid")
            self.cluster = kwargs.get("cluster")
            self.id = objects_attr.id
            self.object_type = objects_attr.object_type
            self._object_data = None

        async def __aenter__(self):
            if self.cluster:
                await self.cluster.acquire_lock()
            else:
                logger.info("No cluster instance provided, saving locally only")
            if self.id:
                await self.refresh()
            return self

        async def __aexit__(self, exc_type, exc_value, exc_tb):
            if self.cluster:
                try:
                    failed_tasks = await self.cluster.add_tasks(
                        defaults.IN_MEMORY_DB["objects_tasks"]
                    )
                    defaults.IN_MEMORY_DB["objects_tasks"] = []
                    defaults.IN_MEMORY_DB["failed_objects_tasks"] += list(failed_tasks)
                    if failed_tasks:
                        raise Exception(
                            "Some tasks could not be processed and remain in the queue"
                        )
                finally:
                    await self.cluster.release()
            else:
                defaults.IN_MEMORY_DB["objects_tasks"] = []

        def get(self):
            return self._object_data

        async def refresh(self) -> None:
            if self.id:
                async with TinyDB(**TINYDB_PARAMS) as db:
                    object_data = []
                    object_data.append(
                        objects_model.model_classes["base"][self.object_type].parse_obj(
                            db.table(self.object_type).get(
                                Query().id.one_of(ensure_list(self.id))
                            )
                        )
                    )
                    if isinstance(self.id, str):
                        self._object_data = object_data.pop()
                    else:
                        self._object_data = object_data.pop()

        @object_task
        async def delete(self):
            async with TinyDB(**TINYDB_PARAMS) as db:
                return db.table(self.object_type).remove(
                    Query().id.one_of(ensure_list(self.id))
                )

        @object_task
        async def patch(self, data: dict):
            validated_data = objects_model.model_classes["patch"][
                self.object_type
            ].parse_obj(data)

            async with TinyDB(**TINYDB_PARAMS) as db:
                for object_id in ensure_list(self.id):
                    name_conflict = db.table(self.object_type).search(
                        (Query().name == validated_data.name)
                        & (Query().id != object_id)
                    )
                    if name_conflict:
                        raise ValueError("name", "The provided object name exists")
                    db.table(self.object_type).update(
                        validated_data.dict(exclude_none=True),
                        Query().id == object_id,
                    )

        @object_task
        @validate_call
        async def create(self, data: dict):
            validated_data = objects_model.ObjectAdd.parse_obj(data).dict()

            if self._enfore_uuid:
                validated_data["id"] = self._enfore_uuid

            async with TinyDB(**TINYDB_PARAMS) as db:
                name_conflict = db.table(self.object_type).search(
                    Query().name == validated_data["name"]
                )
                if name_conflict:
                    raise ValueError("name", "The provided object name exists")
                db.table(self.object_type).insert(validated_data)

            return validated_data["id"]

    @validate_call
    async def exists(
        self,
        name: str | list,
        object_type: Literal[*objects_model.model_classes["types"]],
    ) -> bool:
        names = ensure_list(name)
        async with TinyDB(**TINYDB_PARAMS) as db:
            matches = db.table(object_type).search(
                Query().name.one_of(ensure_list(names))
            )
            return set([m["name"] for m in matches]) == set(names)

    @validate_call
    async def search(
        self,
        object_type: Literal[*objects_model.model_classes["types"]],
        q: constr(strip_whitespace=True, min_length=0) = Field(...),
    ):
        in_q = lambda s: q in s
        async with TinyDB(**TINYDB_PARAMS) as db:
            matches = db.table(object_type).search(Query().name.test(in_q))
            _parsed = []
            for o in matches:
                _parsed.append(
                    objects_model.model_classes["base"][object_type].parse_obj(o)
                )

        return _parsed
