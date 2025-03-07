from components.models.objects import (
    ObjectIdList,
    model_classes,
    validate_call,
    UUID,
    Literal,
)
from components.web.utils.quart import current_app, session
from components.utils import ensure_list, merge_models
from components.cache import buster
from components.database import *


@validate_call
async def get(
    object_type: Literal[*model_classes["types"]],
    object_id: UUID | list[UUID],
    permission_validation=True,
):
    get_objects = ObjectIdList(object_id=object_id).object_id
    db_params = evaluate_db_params()

    if current_app and session.get("id"):
        user_id = session["id"]
    else:
        user_id = "anonymous"

    if not user_id in IN_MEMORY_DB["OBJECTS_CACHE"]:
        IN_MEMORY_DB["OBJECTS_CACHE"][user_id] = dict()

    async with TinyDB(**db_params) as db:
        found_objects = db.table(object_type).search(Query().id.one_of(get_objects))

    object_data = []

    for o in found_objects:
        o_parsed = model_classes["base"][object_type].model_validate(o)

        if (
            not "system" in session["acl"]
            and permission_validation == True
            and user_id not in o_parsed.details.assigned_users
        ):
            continue

        for k, v in o_parsed.details.model_dump(mode="json").items():
            if k == "assigned_domain":
                if not v in IN_MEMORY_DB["OBJECTS_CACHE"][user_id]:
                    IN_MEMORY_DB["OBJECTS_CACHE"][user_id][v] = await get(
                        object_type="domains",
                        object_id=v,
                        permission_validation=False,
                    )

                o_parsed.details.assigned_domain = IN_MEMORY_DB["OBJECTS_CACHE"][
                    user_id
                ][v]
            elif k in ["assigned_arc_keypair", "assigned_dkim_keypair"] and v:
                if not v in IN_MEMORY_DB["OBJECTS_CACHE"][user_id]:
                    IN_MEMORY_DB["OBJECTS_CACHE"][user_id][v] = await get(
                        object_type="keypairs",
                        object_id=v,
                        permission_validation=False,
                    )
                setattr(o_parsed.details, k, IN_MEMORY_DB["OBJECTS_CACHE"][user_id][v])
            elif k == "assigned_emailusers" and v:
                o_parsed.details.assigned_emailusers = []
                for u in ensure_list(v):
                    if not u in IN_MEMORY_DB["OBJECTS_CACHE"][user_id]:
                        IN_MEMORY_DB["OBJECTS_CACHE"][user_id][u] = await get(
                            object_type="emailusers",
                            object_id=u,
                            permission_validation=False,
                        )
                    o_parsed.details.assigned_emailusers.append(
                        IN_MEMORY_DB["OBJECTS_CACHE"][user_id][u]
                    )

        object_data.append(o_parsed)

    if len(object_data) == 1:
        return object_data.pop()

    return object_data if object_data else None


async def delete(
    object_type: Literal[*model_classes["types"]],
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
        buster([o.id for o in delete_objects])
        return db.table(object_type).remove(
            Query().id.one_of([o.id for o in delete_objects])
        )


@validate_call
async def patch(
    object_type: Literal[*model_classes["types"]],
    object_id: UUID | list[UUID],
    data: dict,
):
    assert current_app and session.get("id")

    to_patch_objects = [o for o in ensure_list(await get(object_type, object_id))]
    db_params = evaluate_db_params()

    for to_patch in to_patch_objects:
        if not "system" in session["acl"]:
            if not "details" in data:
                data["details"] = dict()
            for f in model_classes["system_fields"][object_type]:
                data["details"][f] = getattr(to_patch.details, f)

        patch_data = model_classes["patch"][object_type].model_validate(data)

        patched_object = merge_models(
            to_patch, patch_data
        )  # returns updated to_patch model

        conflicts = await search(
            object_type=object_type,
            match_all={
                f: getattr(patched_object.details, f)
                for f in model_classes["unique_fields"][object_type]
            },
            fully_resolve=False,
        )
        if [o.id for o in conflicts if o.id != patched_object.id]:
            raise ValueError(
                f"details.{model_classes['unique_fields'][object_type][0]}",
                "The provided object exists",
            )

        if object_type == "domains":
            if "system" in session["acl"]:
                addresses_in_domain = await search(
                    object_type="addresses",
                    match_all={"assigned_domain": patched_object.id},
                    fully_resolve=False,
                )
                if (
                    patched_object.details.n_mailboxes
                    and len(addresses_in_domain) > patched_object.details.n_mailboxes
                ):
                    raise ValueError(
                        f"details.n_mailboxes",
                        f"Cannot reduce allowed mailboxes below {len(addresses_in_domain)}",
                    )

            else:
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
                        if not "system" in session["acl"]:
                            if not await get("keypairs", to_patch_obj_keypair_id):
                                raise ValueError(
                                    f"details.{attr}",
                                    f"Cannot unassign a non-permitted keypair",
                                )
                            if not await get("keypairs", patched_obj_keypair_id):
                                raise ValueError(
                                    f"details.{attr}",
                                    f"Cannot assign non-permitted keypair",
                                )
        if object_type == "addresses":
            if not "system" in session["acl"]:
                if (
                    patched_object.details.assigned_domain
                    != to_patch.details.assigned_domain.id
                ):  # only when assigned_domain changed
                    if (
                        not len(
                            await get(
                                "domains",
                                [
                                    patched_object.details.assigned_domain,
                                    to_patch.details.assigned_domain.id,
                                ],
                            )
                        )
                        == 2
                    ):
                        # disallow a change to a permitted domain if the current domain is not permitted
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
                        _ = await get(
                            object_type="emailusers",
                            object_id=emailuser,
                            permission_validation=False,
                        )
                        if session["id"] not in _.details.assigned_users:
                            non_permitted_users.add(_.name if _ else "<unknown>")

                    if non_permitted_users:
                        # disallow a change to a permitted domain if the current domain is not permitted
                        raise ValueError(
                            "details.assigned_emailusers",
                            f"You are not allow to change email user assignments for {', '.join(non_permitted_users)} of address {to_patch.details.local_part}",
                        )
            if (
                patched_object.details.assigned_domain
                != to_patch.details.assigned_domain.id
            ):
                addresses_in_new_domain_now = await search(
                    object_type="addresses",
                    match_all={
                        "assigned_domain": patched_object.details.assigned_domain
                    },
                    fully_resolve=False,
                )
                new_domain_data = await get(
                    object_type="domains",
                    object_id=patched_object.details.assigned_domain,
                    permission_validation=True,
                )
                if (
                    new_domain_data.details.n_mailboxes
                    and new_domain_data.details.n_mailboxes
                    < (len(addresses_in_new_domain_now) + 1)
                ):
                    raise ValueError(
                        f"details.assigned_domain",
                        "The domain's mailbox limit is reached",
                    )

        async with TinyDB(**db_params) as db:
            db.table(object_type).update(
                patched_object.model_dump(
                    mode="json", exclude_none=True, exclude={"name", "id", "created"}
                ),
                Query().id == to_patch.id,
            )
            buster([o.id for o in to_patch_objects])

    return [o.id for o in to_patch_objects]


async def create(
    object_type: Literal[*model_classes["types"]],
    data: dict,
):
    assert current_app and session.get("id")

    db_params = evaluate_db_params()

    if not "details" in data:
        data["details"] = dict()

    data["details"]["assigned_users"] = session["id"]

    create_object = model_classes["add"][object_type].model_validate(data)

    conflicts = await search(
        object_type=object_type,
        match_all={
            f: getattr(create_object.details, f)
            for f in model_classes["unique_fields"][object_type]
        },
        fully_resolve=False,
    )
    if [o.id for o in conflicts]:
        raise ValueError(
            f"details.{model_classes['unique_fields'][object_type][0]}",
            "The provided object exists",
        )

    if object_type == "addresses":
        if not "system" in session["acl"]:
            if not await get("domains", create_object.details.assigned_domain):
                raise ValueError("name", "The provided domain is unavailable")

        addresses_in_domain = await search(
            object_type="addresses",
            match_all={"assigned_domain": create_object.details.assigned_domain},
            fully_resolve=False,
        )
        domain_data = await get(
            object_type="domains",
            object_id=create_object.details.assigned_domain,
            permission_validation=True,
        )

        domain_assigned_users = set(domain_data.details.assigned_users)
        domain_assigned_users.add(session["id"])
        create_object.details.assigned_users = list(domain_assigned_users)

        if domain_data.details.n_mailboxes and domain_data.details.n_mailboxes < (
            len(addresses_in_domain) + 1
        ):
            raise ValueError(
                f"details.assigned_domain",
                "The domain's mailbox limit is reached",
            )

    if object_type == "domains":
        if not "system" in session["acl"]:
            raise ValueError("name", "You need system permission to create a domain")

    async with TinyDB(**db_params) as db:
        insert_data = create_object.model_dump(mode="json")
        db.table(object_type).insert(insert_data)

    try:
        del IN_MEMORY_DB["FORM_OPTIONS_CACHE"][session.get("id")][object_type]
    finally:
        return insert_data["id"]


async def search(
    object_type: Literal[*model_classes["types"]],
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
                    return any(item in ensure_list(current_data[key]) for item in value)

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
            _parsed.append(model_classes["base"][object_type].model_validate(o))
        return _parsed
