import asyncio
import models.objects as objects_model
import re

from config import defaults
from config.database import *
from pydantic import Field, constr, validate_call, TypeAdapter
from tools import cluster_task, evaluate_db_params, whoami, TaskModel
from typing import Literal
from utils.datetimes import ntime_utc_now
from utils.helpers import ensure_list, merge_deep
from uuid import UUID


@validate_call
async def evaluate_permitted_objects(
    user_uuid: UUID, object_types: list = objects_model.model_classes["types"]
):
    from tools.users import Users

    user_id = str(user_uuid)
    user = await Users.user(id=user_id).get()

    permissions = {"acl": user.acl}
    permissions.update(
        {
            object_type: objects
            for object_type, objects in [
                (
                    ot,
                    await Objects().search(
                        object_type=ot,
                        q="",
                        filter_details={"assigned_users": [user.id]}
                        if not "system" in user.acl
                        else {},
                    ),
                )
                for ot in object_types
            ]
        }
    )
    return permissions


class Objects:
    def __init__(self):
        self.db_params = evaluate_db_params()

    class create:
        @whoami
        def __init__(self, *args, **kwargs):
            self.db_params = evaluate_db_params()

            # magic happens in cluster_task
            # some required init_kwargs are injected automatically
            for key, value in kwargs.items():
                setattr(self, key, value)

            TypeAdapter(Literal[*objects_model.model_classes["types"]]).validate_python(
                self.object_type
            )

        @cluster_task("objects_create_object", enforce_uuid=True)
        async def object(self, data: dict):
            permitted_objects = await evaluate_permitted_objects(
                user_uuid=self.user_id, object_types=["domains"]
            )

            if not "details" in data:
                data["details"] = {"assigned_users": self.user_id}
            elif not "assigned_users" in data["details"]:
                data["details"]["assigned_users"] = self.user_id

            validated_data = (
                objects_model.model_classes["add"][self.object_type]
                .parse_obj(data)
                .dict()
            )

            if self.object_type == "addresses":
                if not validated_data["domain"] in [
                    domain.name for domain in permitted_objects["domains"]
                ]:
                    raise ValueError("name", "The provided domain is unavailable")

            if self.object_type == "domains":
                if not "system" in permitted_objects["acl"]:
                    raise ValueError(
                        "name", "You need system permission to create a domain"
                    )

            if getattr(self, "uuid", None):
                validated_data["id"] = self.uuid

            async with TinyDB(**self.db_params) as db:
                if db.table(self.object_type).get(
                    Query().name == validated_data["name"]
                ):
                    raise ValueError("name", "The provided object name exists")
                db.table(self.object_type).insert(validated_data)

            return validated_data["id"]

    class object:
        @whoami
        def __init__(self, *args, **kwargs):
            self.db_params = evaluate_db_params()

            for key, value in kwargs.items():
                setattr(self, key, value)

            objects_attr = objects_model._Objects_attr.parse_obj(kwargs)
            self.id = objects_attr.id
            self.object_type = objects_attr.object_type

        async def get(self):
            permitted_objects = await evaluate_permitted_objects(
                user_uuid=self.user_id, object_types=[self.object_type]
            )
            permitted_ids = [
                o.id
                for o in permitted_objects[self.object_type]
                if o.id in ensure_list(self.id)
            ]

            async with TinyDB(**self.db_params) as db:
                object_data = []
                for obj in db.table(self.object_type).search(
                    Query().id.one_of(permitted_ids)
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
            delete_objects = [o for o in ensure_list(await self.get())]

            if self.object_type == "domains":
                for o in delete_objects:
                    addresses = await Objects().search(
                        q=f"@{o.name}", object_type="addresses"
                    )
                    if o.name in [address.domain for address in addresses]:
                        raise ValueError("name", f"Domain {o.name} is not empty")

            async with TinyDB(**self.db_params) as db:
                return db.table(self.object_type).remove(
                    Query().id.one_of([o.id for o in delete_objects])
                )

        @cluster_task("objects_object_patch")
        async def patch(self, data: dict):
            patch_objects = [o for o in ensure_list(await self.get())]
            permitted_objects = await evaluate_permitted_objects(user_uuid=self.user_id)

            import email_validator

            email_validator.TEST_ENVIRONMENT = True
            validate_email = email_validator.validate_email

            async with TinyDB(**self.db_params) as db:
                for patch_object in patch_objects:
                    validated_data = objects_model.model_classes["patch"][
                        self.object_type
                    ].model_validate(merge_deep(patch_object.dict(), data))

                    if (
                        self.object_type == "addresses"
                        and not validated_data.domain
                        in [d.name for d in permitted_objects["domains"]]
                    ):
                        raise ValueError(
                            "name",
                            f"The provided domain name {ascii_domain} for object {validated_data.name} is unavailable",
                        )

                    name_conflict = db.table(self.object_type).search(
                        (Query().name == validated_data.name)
                        & (Query().id != patch_object.id)
                    )
                    if name_conflict:
                        raise ValueError("name", "The provided object name exists")

                    db.table(self.object_type).update(
                        validated_data.dict(exclude_none=True),
                        Query().id == patch_object.id,
                    )

                    if self.object_type == "domains":
                        for obj in db.table("addresses").search(
                            Query().domain == current_data.name
                        ):
                            db.table("addresses").update(
                                {
                                    "name": "{ascii_local_part}@{domain}".format(
                                        ascii_local_part=validate_email(
                                            obj["name"]
                                        ).ascii_local_part,
                                        domain=validated_data.name,
                                    ),
                                    "domain": validated_data.name,
                                },
                                Query().id == obj["id"],
                            )

            return [o.id for o in patch_objects]

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
