import asyncio
import models.objects as objects_model
import re

from config import defaults
from config.logs import logger
from config.database import *
from pydantic import Field, constr, validate_call, TypeAdapter
from tools import cluster_task, evaluate_db_params, TaskModel
from typing import Literal
from quart import current_app, session
from utils.datetimes import ntime_utc_now
from utils.helpers import ensure_list, merge_deep
from uuid import UUID


@validate_call
async def user_permitted_objects(user_id: UUID | None = None):
    from tools.users import Users

    if not user_id and current_app and session.get("id"):
        user_id = session["id"]

    user = await Users.user(id=str(user_id)).get()
    permissions = {
        "_meta": {
            "user_id": user.id,
            "user_acl": user.acl,
        }
    }
    permissions.update(
        {
            object_type: objects
            for object_type, objects in [
                (
                    ot,
                    await search(
                        object_type=ot,
                        q="",
                        filter_details={"assigned_users": [user.id]}
                        if not "system" in user.acl
                        else {},
                    ),
                )
                for ot in objects_model.model_classes["types"]
            ]
        }
    )
    return permissions


@validate_call
async def get(
    object_type: Literal[*objects_model.model_classes["types"]],
    object_id: UUID | list[UUID],
):
    object_id = (
        objects_model.ObjectIdList(object_id=object_id).object_id if object_id else None
    )
    permitted_objects = await user_permitted_objects()
    db_params = evaluate_db_params()
    get_objects = [o.id for o in permitted_objects[object_type] if o.id in object_id]

    async with TinyDB(**db_params) as db:
        object_data = []
        for obj in db.table(object_type).search(Query().id.one_of(get_objects)):
            object_data.append(
                objects_model.model_classes["base"][object_type].parse_obj(obj)
            )
        if len(object_data) == 1:
            return object_data.pop()
        else:
            return object_data


async def delete(
    object_type: Literal[*objects_model.model_classes["types"]],
    object_id: UUID | list[UUID],
):
    delete_objects = [o for o in ensure_list(await get(object_type, object_id))]
    db_params = evaluate_db_params()

    if object_type == "domains":
        for o in delete_objects:
            addresses = await search(object_type="addresses", q="")
            if o.id in [address.assigned_domain for address in addresses]:
                raise ValueError("name", f"Domain {o.name} is not empty")

    async with TinyDB(**db_params) as db:
        return db.table(object_type).remove(
            Query().id.one_of([o.id for o in delete_objects])
        )


@validate_call
async def patch(
    object_type: Literal[*objects_model.model_classes["types"]],
    object_id: UUID | list[UUID],
    data: dict,
):
    patch_objects = [o for o in ensure_list(await get(object_type, object_id))]
    db_params = evaluate_db_params()
    permitted_objects = await user_permitted_objects()

    async with TinyDB(**db_params) as db:
        if not "system" in permitted_objects["_meta"]["user_acl"]:
            data.setdefault("details", {}).pop("assigned_users", None)

        for patch_object in patch_objects:
            validated_data = objects_model.model_classes["patch"][
                object_type
            ].model_validate(merge_deep(patch_object.dict(), data))

            if object_type == "addresses" and not validated_data.assigned_domain in [
                d.id for d in permitted_objects["domains"]
            ]:
                raise ValueError(
                    "name",
                    f"The provided domain name {ascii_domain} for object {validated_data.name} is unavailable",
                )

            if object_type == "addresses":
                name_conflict = db.table(object_type).search(
                    (Query().name == validated_data.name)
                    & (Query().id != patch_object.id)
                    & (Query().assigned_domain == validated_data.assigned_domain)
                )
            else:
                name_conflict = db.table(object_type).search(
                    (Query().name == validated_data.name)
                    & (Query().id != patch_object.id)
                )
            if name_conflict:
                raise ValueError("name", "The provided object name exists")

            db.table(object_type).update(
                validated_data.dict(exclude_none=True),
                Query().id == patch_object.id,
            )

    return [o.id for o in patch_objects]


async def search(
    object_type: Literal[*objects_model.model_classes["types"]],
    q: constr(strip_whitespace=True, min_length=0) = Field(...),
    filter_details: dict = {},
):
    db_params = evaluate_db_params()

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

    async with TinyDB(**db_params) as db:
        matches = db.table(object_type).search(query)
        _parsed = []
        for o in matches:
            _parsed.append(
                objects_model.model_classes["base"][object_type].parse_obj(o)
            )

    return _parsed


async def create(
    object_type: Literal[*objects_model.model_classes["types"]],
    data: dict,
):
    db_params = evaluate_db_params()
    permitted_objects = await user_permitted_objects()
    data.setdefault("details", {}).setdefault("assigned_users", []).append(
        permitted_objects["_meta"]["user_id"]
    )

    validated_data = (
        objects_model.model_classes["add"][object_type].parse_obj(data).dict()
    )

    if object_type == "addresses":
        if not validated_data["assigned_domain"] in [
            domain.id for domain in permitted_objects["domains"]
        ]:
            raise ValueError("name", "The provided domain is unavailable")

    if object_type == "domains":
        if not "system" in permitted_objects["_meta"]["user_acl"]:
            raise ValueError("name", "You need system permission to create a domain")

    async with TinyDB(**db_params) as db:
        if object_type == "addresses":
            if db.table(object_type).get(
                (Query().name == validated_data["name"])
                & (Query().assigned_domain == validated_data["assigned_domain"])
            ):
                raise ValueError("name", "The provided address exists in this domain")
        else:
            if db.table(object_type).get(Query().name == validated_data["name"]):
                raise ValueError("name", "The provided object name exists")
        db.table(object_type).insert(validated_data)

    return validated_data["id"]
