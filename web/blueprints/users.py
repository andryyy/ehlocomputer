import re

from utils.cluster.http_lock import ClusterLock
from models.tables import TableSearchHelper
from models.forms.users import UserProfile
from pydantic import ValidationError
from quart import Blueprint, current_app as app, render_template, request
from tools.users import (
    search as search_users,
    get as _get_user,
    patch as _patch_user,
    patch_credential as _patch_credential,
    patch_profile as _patch_profile,
)
from utils import wrappers
from utils.helpers import batch, ensure_list
from web.helpers import render_or_json, trigger_notification, validation_error


blueprint = Blueprint("users", __name__, url_prefix="/system/users")


@blueprint.context_processor
def load_context():
    context = dict()
    context["schemas"] = {"user_profile": UserProfile.model_json_schema()}
    return context


@blueprint.route("/<user_id>")
@wrappers.acl("system")
async def get_user(user_id: str):
    try:
        user = await _get_user(user_id=user_id)
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
@wrappers.acl("system")
async def get_users():
    try:
        (
            search_model,
            page,
            page_size,
            sort_attr,
            sort_reverse,
            filters,
        ) = TableSearchHelper(request.form_parsed, "users", default_sort_attr="login")
    except ValidationError as e:
        return validation_error(e.errors())

    if request.method == "POST":
        matched_users = [m.dict() for m in await search_users(name=search_model.q)]

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
@wrappers.acl("system")
async def delete_user(user_id: str | None = None):
    if request.method == "POST":
        user_ids = request.form_parsed.get("id")

    try:
        async with ClusterLock("users"):
            for user_id in ensure_list(user_ids):
                await _delete_user(user_id=user_id)

    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    return trigger_notification(
        level="success",
        response_code=204,
        title="User removed",
        message=f"{len(user_ids)} user{'s' if len(user_ids) > 1 else ''} removed",
    )


@blueprint.route("/<user_id>/credential/<hex_id>", methods=["PATCH"])
@wrappers.acl("system")
async def patch_user_credential(user_id: str, hex_id: str):
    try:
        async with ClusterLock("credentials"):
            await _patch_credential(
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
@wrappers.acl("system")
async def patch_user(user_id: str | None = None):
    try:
        if not user_id:
            user_id = request.form_parsed.get("id")

        async with ClusterLock("users"):
            await _patch_user(user_id=user_id, data=request.form_parsed)
            await _patch_profile(
                user_id=user_id, data=request.form_parsed.get("profile", {})
            )

    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    app.config["SESSION_VALIDATED"].pop(user_id, None)

    return trigger_notification(
        level="success",
        response_code=204,
        title="User modified",
        message=f"User was updated",
    )
