import asyncio
import models.objects as objects_model
import re

from config import defaults
from config.database import *
from config.logs import logger
from pydantic import Field, constr, validate_call, TypeAdapter
from tools import cluster_task, evaluate_db_params
from typing import Literal
from utils.datetimes import ntime_utc_now
from utils.helpers import ensure_list, merge_deep


class Objects:
    def __init__(self):
        self.db_params = evaluate_db_params()

    class create:
        def __init__(self, *args, **kwargs):
            self.db_params = evaluate_db_params()

            for key, value in kwargs.items():
                setattr(self, key, value)

            TypeAdapter(Literal[*objects_model.model_classes["types"]]).validate_python(
                self.object_type
            )

        @cluster_task("objects_create_object", enforce_uuid=True)
        async def object(self, data: dict):
            validated_data = (
                objects_model.model_classes["add"][self.object_type]
                .parse_obj(data)
                .dict()
            )

            if getattr(self, "uuid", None):
                validated_data["id"] = self.uuid

            async with TinyDB(**self.db_params) as db:
                name_conflict = db.table(self.object_type).search(
                    Query().name == validated_data["name"]
                )
                if name_conflict:
                    raise ValueError("name", "The provided object name exists")
                db.table(self.object_type).insert(validated_data)

            return validated_data["id"]

    class object:
        def __init__(self, *args, **kwargs):
            self.db_params = evaluate_db_params()

            for key, value in kwargs.items():
                setattr(self, key, value)

            objects_attr = objects_model._Objects_attr.parse_obj(kwargs)
            self.id = objects_attr.id
            self.object_type = objects_attr.object_type

        async def get(self) -> None:
            async with TinyDB(**self.db_params) as db:
                object_data = []
                for obj in db.table(self.object_type).search(
                    Query().id.one_of(ensure_list(self.id))
                ):
                    object_data.append(
                        objects_model.model_classes["base"][self.object_type].parse_obj(
                            obj
                        )
                    )
                if len(object_data) == 1:
                    return object_data.pop()
                else:
                    return object_data

        @cluster_task("objects_object_delete")
        async def delete(self):
            async with TinyDB(**self.db_params) as db:
                return db.table(self.object_type).remove(
                    Query().id.one_of(ensure_list(self.id))
                )

        @cluster_task("objects_object_patch")
        async def patch(self, data: dict):
            async with TinyDB(**self.db_params) as db:
                for object_id in ensure_list(self.id):
                    current_data = (
                        objects_model.model_classes["base"][self.object_type]
                        .model_validate(
                            db.table(self.object_type).get(Query().id == object_id)
                        )
                        .dict()
                    )

                    validated_data = objects_model.model_classes["patch"][
                        self.object_type
                    ].model_validate(merge_deep(current_data, data))

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

    @validate_call
    async def search(
        self,
        object_type: Literal[*objects_model.model_classes["types"]],
        q: constr(strip_whitespace=True, min_length=0) = Field(...),
        filter_details: dict = {},
    ):
        def search_q(s):
            return q in s

        def search_details(s):
            def match(key, value, current_data):
                if key in current_data:
                    if isinstance(value, list):
                        return any(item in current_data[key] for item in value)
                    return current_data[key] == value

                for sub_key, sub_value in current_data.items():
                    if isinstance(sub_value, dict):
                        if match(key, value, sub_value):  # Recursive call
                            return True
                return False

            return all(match(k, v, s) for k, v in filter_details.items())

        if filter_details:
            query = ((Query().name.test(search_q)) | (Query().id.test(search_q))) & (
                Query().details.test(search_details)
            )
        else:
            query = (Query().name.test(search_q)) | (Query().id.test(search_q))

        async with TinyDB(**self.db_params) as db:
            matches = db.table(object_type).search(query)
            _parsed = []
            for o in matches:
                _parsed.append(
                    objects_model.model_classes["base"][object_type].parse_obj(o)
                )

        return _parsed
