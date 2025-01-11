import asyncio
import models.objects as objects_model
import re

from config import defaults
from config.logs import logger
from config.database import *
from pydantic import Field, constr, validate_call
from tools import cluster_task, evaluate_db_params, TaskModel
from typing import Literal
from quart import current_app, session
from utils.datetimes import ntime_utc_now
from utils.helpers import ensure_list, merge_models
from uuid import UUID
from functools import reduce


@validate_call
async def user_permitted_objects(user_id: UUID | None = None):
    from tools.users import get as get_user

    if not user_id and current_app and session.get("id"):
        user_id = session["id"]

    user = await get_user(user_id=user_id)
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
                        match_all={"assigned_users": [user.id]}
                        if not "system" in user.acl
                        else {},
                        fully_resolve=False,
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
    permission_validation=True,
):
    get_objects = objects_model.ObjectIdList(object_id=object_id).object_id
    permitted_objects = await user_permitted_objects()
    db_params = evaluate_db_params()

    if permission_validation == True:
        get_objects = [
            o.id for o in permitted_objects[object_type] if o.id in get_objects
        ]

    async with TinyDB(**db_params) as db:
        found_objects = db.table(object_type).search(Query().id.one_of(get_objects))

    object_data = []
    for o in found_objects:
        o_parsed = objects_model.model_classes["base"][object_type].parse_obj(o)
        for k, v in o_parsed.details.model_dump(mode="json").items():
            if k == "assigned_domain":
                domain_data = await get(
                    object_type="domains", object_id=v, permission_validation=False
                )
                o_parsed.details.assigned_domain = domain_data
            elif k in ["assigned_arc_keypair", "assigned_dkim_keypair"] and v:
                keypair_data = await get(
                    object_type="keypairs", object_id=v, permission_validation=False
                )
                setattr(o_parsed.details, k, keypair_data)
            elif k == "assigned_emailusers" and v:
                o_parsed.details.assigned_emailusers = []
                for u in ensure_list(v):
                    emailuser_data = await get(
                        object_type="emailusers",
                        object_id=v,
                        permission_validation=False,
                    )
                    o_parsed.details.assigned_emailusers.append(emailuser_data)

        object_data.append(o_parsed)

    if len(object_data) == 1:
        return object_data.pop()

    return object_data if object_data else None


async def delete(
    object_type: Literal[*objects_model.model_classes["types"]],
    object_id: UUID | list[UUID],
):
    delete_objects = [o for o in ensure_list(await get(object_type, object_id))]
    db_params = evaluate_db_params()

    if object_type == "domains":
        for o in delete_objects:
            addresses = await search(object_type="addresses", fully_resolve=False)
            if o.id in [address.details.assigned_domain for address in addresses]:
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
    to_patch_objects = [o for o in ensure_list(await get(object_type, object_id))]
    db_params = evaluate_db_params()
    permitted_objects = await user_permitted_objects()

    for to_patch in to_patch_objects:
        if not "system" in permitted_objects["_meta"]["user_acl"]:
            data.setdefault("details", {}).setdefault(
                "assigned_users", to_patch.details.assigned_users
            )

        patch_data = objects_model.model_classes["patch"][object_type].parse_obj(data)
        patched_object = merge_models(to_patch, patch_data)

        conflict_queries = [Query().id != to_patch.id]
        unique_fields = patched_object.details._unique_fields

        if isinstance(unique_fields, tuple):
            for f in unique_fields:
                conflict_queries.append(
                    (getattr(Query().details, f) == getattr(patched_object.details, f))
                )
        else:
            conflict_queries.append(
                getattr(Query().details, unique_fields)
                == getattr(patched_object.details, unique_fields)
            )

        conflict_query = reduce(lambda q1, q2: q1 & q2, conflict_queries)

        async with TinyDB(**db_params) as db:
            if db.table(object_type).get(conflict_query):
                if isinstance(unique_fields, tuple):
                    unique_fields = unique_fields[0]
                raise ValueError(
                    f"details.{unique_fields}", "The provided object exists"
                )

        if (
            object_type == "domains"
            and not "system" in permitted_objects["_meta"]["user_acl"]
        ):
            for attr in ["assigned_dkim_keypair", "assigned_arc_keypair"]:
                # keypairs default to "", verify
                if attr not in data.get("details", {}):
                    continue

                patched_obj_keypair = getattr(patched_object.details, attr)
                patched_obj_keypair_id = (
                    patched_obj_keypair.id
                    if hasattr(patched_obj_keypair, "id")
                    else patched_obj_keypair
                )

                to_patch_obj_keypair = getattr(to_patch.details, attr)
                to_patch_obj_keypair_id = (
                    to_patch_obj_keypair.id
                    if hasattr(to_patch_obj_keypair, "id")
                    else to_patch_obj_keypair
                )

                if patched_obj_keypair_id != to_patch_obj_keypair_id:
                    if any(
                        keypair not in [k.id for k in permitted_objects["keypairs"]]
                        for keypair in [
                            patched_obj_keypair_id,
                            to_patch_obj_keypair_id,
                        ]
                    ):
                        if patched_obj_keypair_id:
                            non_permitted_keypair = await get(
                                object_type="keypairs",
                                object_id=patched_obj_keypair_id,
                                permission_validation=False,
                            )
                        if not patched_obj_keypair_id:
                            raise ValueError(
                                f"details.{attr}",
                                f"Cannot unassign non-permitted keypair from object {to_patch.details.domain}",
                            )
                        raise ValueError(
                            f"details.{attr}",
                            f"Cannot assign non-permitted keypair {non_permitted_keypair.name} to object {to_patch.details.domain}",
                        )
        if (
            object_type == "addresses"
            and not "system" in permitted_objects["_meta"]["user_acl"]
        ):
            if (
                patched_object.details.assigned_domain
                != to_patch.details.assigned_domain.id
            ):  # only when assigned_domain changed
                if any(
                    domain not in [d.id for d in permitted_objects["domains"]]
                    for domain in [
                        patched_object.details.assigned_domain,
                        to_patch.details.assigned_domain.id,
                    ]
                ):  # disallow a change to a permitted domain if the current domain is not permitted
                    raise ValueError(
                        "details.assigned_domain",
                        f"Cannot assign selected domain for object {to_patch.details.local_part}",
                    )

            if set(patched_object.details.assigned_emailusers) != set(
                [u.id for u in to_patch.details.assigned_emailusers]
            ):  # only when assigned_emailusers changed
                non_permitted_users = set()

                for emailuser in [
                    *patched_object.details.assigned_emailusers,
                    *[u.id for u in to_patch.details.assigned_emailusers],
                ]:
                    if emailuser and emailuser not in [
                        u.id for u in permitted_objects["emailusers"]
                    ]:
                        _ = await get(
                            object_type="emailusers",
                            object_id=emailuser,
                            permission_validation=False,
                        )
                        non_permitted_users.add(_.name if _ else "<unknown>")

                if non_permitted_users:
                    # disallow a change to a permitted domain if the current domain is not permitted
                    raise ValueError(
                        "details.assigned_emailusers",
                        f"You are not allow to change email user assignments for {', '.join(non_permitted_users)} of address {to_patch.details.local_part}",
                    )

        async with TinyDB(**db_params) as db:
            db.table(object_type).update(
                patched_object.dict(exclude_none=True),
                Query().id == to_patch.id,
            )

    return [o.id for o in to_patch_objects]


async def create(
    object_type: Literal[*objects_model.model_classes["types"]],
    data: dict,
):
    db_params = evaluate_db_params()
    permitted_objects = await user_permitted_objects()

    data.setdefault("details", {})["assigned_users"] = [
        permitted_objects["_meta"]["user_id"]
    ]

    create_object = objects_model.model_classes["add"][object_type].parse_obj(data)

    unique_fields = create_object.details._unique_fields
    if isinstance(unique_fields, tuple):
        queries = []
        for f in unique_fields:
            queries.append(
                (getattr(Query().details, f) == getattr(create_object.details, f))
            )
        query = reduce(lambda q1, q2: q1 & q2, queries)
    else:
        query = getattr(Query().details, unique_fields) == getattr(
            create_object.details, unique_fields
        )

    async with TinyDB(**db_params) as db:
        if db.table(object_type).get(query):
            if isinstance(unique_fields, tuple):
                unique_fields = unique_fields[0]
            raise ValueError(f"details.{unique_fields}", "The provided object exists")

    if object_type == "addresses":
        if not create_object.details.assigned_domain in [
            domain.id for domain in permitted_objects["domains"]
        ]:
            raise ValueError("name", "The provided domain is unavailable")

    if object_type == "domains":
        if not "system" in permitted_objects["_meta"]["user_acl"]:
            raise ValueError("name", "You need system permission to create a domain")

    async with TinyDB(**db_params) as db:
        insert_data = create_object.dict()
        db.table(object_type).insert(insert_data)

    return insert_data["id"]


async def search(
    object_type: Literal[*objects_model.model_classes["types"]],
    object_id: UUID | None = None,
    match_all: dict = {},
    match_any: dict = {},
    fully_resolve: bool = False,
):
    db_params = evaluate_db_params()

    def search_object_id(s):
        return (object_id and str(object_id) == s) or not object_id

    def filter_details(s, _any: bool = False):
        def match(key, value, current_data):
            if key in current_data:
                if isinstance(value, list):
                    return any(item in current_data[key] for item in value)
                if key.startswith("assigned_"):
                    return value == current_data[key]
                return value in current_data[key]

            for sub_key, sub_value in current_data.items():
                if isinstance(sub_value, dict):
                    if match(key, value, sub_value):  # Recursive call
                        return True
            return False

        if _any:
            return any(match(k, v, s) for k, v in match_any.items())

        return all(match(k, v, s) for k, v in match_all.items())

    query = Query().id.test(search_object_id)
    if match_all:
        query = query & Query().details.test(filter_details)
    if match_any:
        query = query & Query().details.test(filter_details, True)

    async with TinyDB(**db_params) as db:
        matches = db.table(object_type).search(query)

    if fully_resolve:
        return ensure_list(
            await get(
                object_type=object_type,
                object_id=[o["id"] for o in matches],
                permission_validation=False,
            )
            or []
        )
    else:
        _parsed = []
        for o in matches:
            _parsed.append(
                objects_model.model_classes["base"][object_type].parse_obj(o)
            )
        return _parsed
