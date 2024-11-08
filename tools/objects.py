import asyncio
import models.objects as objects_model
import re

from config import defaults
from config.database import *
from config.logs import logger
from pydantic import Field, constr, validate_call
from tools import cluster_task, evaluate_db_params
from typing import Literal
from utils.datetimes import ntime_utc_now
from utils.helpers import ensure_list
from uuid import UUID


class Objects:
    def __init__(self):
        pass

    class object:
        def __init__(self, *args, **kwargs):
            self.db_params = evaluate_db_params(kwargs)
            self.init_kwargs = kwargs
            objects_attr = objects_model._Objects_attr.parse_obj(kwargs)
            self.id = objects_attr.id
            self.object_type = objects_attr.object_type

            self._enforce_uuid = kwargs.get("_enforce_uuid")

        async def get(self) -> None:
            if self.id:
                async with TinyDB(**self.db_params) as db:
                    object_data = []
                    object_data.append(
                        objects_model.model_classes["base"][self.object_type].parse_obj(
                            db.table(self.object_type).get(
                                Query().id.one_of(ensure_list(self.id))
                            )
                        )
                    )
                    if isinstance(self.id, str):
                        return object_data.pop()
                    else:
                        return object_data
            else:
                raise Exception("No object initialized")

        @cluster_task("objects_object_delete")
        async def delete(self):
            async with TinyDB(**self.db_params) as db:
                return db.table(self.object_type).remove(
                    Query().id.one_of(ensure_list(self.id))
                )

        @cluster_task("objects_object_patch")
        async def patch(self, data: dict):
            validated_data = objects_model.model_classes["patch"][
                self.object_type
            ].parse_obj(data)

            async with TinyDB(**self.db_params) as db:
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

        @cluster_task("objects_object_create", enforce_uuid=True)
        @validate_call
        async def create(self, data: dict):
            validated_data = objects_model.ObjectAdd.parse_obj(data).dict()

            if self._enforce_uuid:
                validated_data["id"] = self._enforce_uuid

            async with TinyDB(**self.db_params) as db:
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
