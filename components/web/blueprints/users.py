import components.users
from components.utils import batch, ensure_list
from components.database import IN_MEMORY_DB
from components.models.users import UserGroups
from components.web.utils import *


blueprint = Blueprint("users", __name__, url_prefix="/system/users")


@blueprint.context_processor
def load_context():
    from components.models.users import UserProfile

    context = dict()
    context["schemas"] = {"user_profile": UserProfile.model_json_schema()}
    return context


@blueprint.route("/groups", methods=["PATCH"])
@acl("system")
async def user_group():
    try:
        request_data = UserGroups.parse_obj(request.form_parsed)

        assigned_to = [
            u
            for u in await components.users.search(name="", join_credentials=False)
            if request_data.name in u.groups
        ]

        assign_to = []
        for user_id in request_data.members:
            assign_to.append(
                await components.users.get(user_id=user_id, join_credentials=False)
            )

        _all = assigned_to + assign_to

        async with ClusterLock(["users", "credentials"], current_app):
            for user in _all:
                user_dict = user.model_dump(mode="json")
                if request_data.name in user_dict["groups"]:
                    user_dict["groups"].remove(request_data.name)

                if (
                    request_data.new_name not in user_dict["groups"]
                    and user in assign_to
                ):
                    user_dict["groups"].append(request_data.new_name)

                await components.users.patch(user_id=user.id, data=user_dict)

        return "", 204

    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])


@blueprint.route("/<user_id>")
@acl("system")
async def get_user(user_id: str):
    try:
        user = await components.users.get(user_id=user_id)
    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    return await render_or_json(
        "system/includes/users/row.html", request.headers, user=user.dict()
    )


@blueprint.route("/")
@blueprint.route("/search", methods=["POST"])
@acl("system")
@formoptions(["users"])
async def get_users():
    try:
        (
            search_model,
            page,
            page_size,
            sort_attr,
            sort_reverse,
            filters,
        ) = table_search_helper(request.form_parsed, "users", default_sort_attr="login")
    except ValidationError as e:
        return validation_error(e.errors())

    if request.method == "POST":
        matched_users = [
            m.dict() for m in await components.users.search(name=search_model.q)
        ]

        user_pages = [
            m
            for m in batch(
                sorted(
                    matched_users,
                    key=lambda x: x.get(sort_attr, "id"),
                    reverse=sort_reverse,
                ),
                page_size,
            )
        ]

        try:
            user_pages[page - 1]
        except IndexError:
            page = len(user_pages)

        users = user_pages[page - 1] if page else user_pages

        return await render_template(
            "system/includes/users/table_body.html",
            data={
                "users": users,
                "page_size": page_size,
                "page": page,
                "pages": len(user_pages),
                "elements": len(matched_users),
            },
        )
    else:
        return await render_template("system/users.html", data={})


@blueprint.route("/delete", methods=["POST"])
@blueprint.route("/<user_id>", methods=["DELETE"])
@acl("system")
async def delete_user(user_id: str | None = None):
    if request.method == "POST":
        user_ids = request.form_parsed.get("id")

    try:
        async with ClusterLock(["users", "credentials"], current_app):
            for user_id in ensure_list(user_ids):
                await components.users.delete(user_id=user_id)

    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    return trigger_notification(
        level="success",
        response_code=204,
        title="User removed",
        message=f"{len(ensure_list(user_ids))} user{'s' if len(ensure_list(user_ids)) > 1 else ''} removed",
    )


@blueprint.route("/<user_id>/credential/<hex_id>", methods=["PATCH"])
@acl("system")
async def patch_user_credential(user_id: str, hex_id: str):
    try:
        async with ClusterLock("credentials", current_app):
            await components.users.patch_credential(
                user_id=user_id,
                hex_id=hex_id,
                data=request.form_parsed,
            )
    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    return trigger_notification(
        level="success",
        response_code=204,
        title="Credential modified",
        message="Credential was modified",
    )


@blueprint.route("/patch", methods=["POST"])
@blueprint.route("/<user_id>", methods=["PATCH"])
@acl("system")
async def patch_user(user_id: str | None = None):
    try:
        if not user_id:
            user_id = request.form_parsed.get("id")

        async with ClusterLock(["users", "credentials"], current_app):
            await components.users.patch(user_id=user_id, data=request.form_parsed)
            await components.users.patch_profile(
                user_id=user_id, data=request.form_parsed.get("profile", {})
            )

    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    IN_MEMORY_DB["SESSION_VALIDATED"].pop(user_id, None)

    return trigger_notification(
        level="success",
        response_code=204,
        title="User modified",
        message=f"User was updated",
    )
