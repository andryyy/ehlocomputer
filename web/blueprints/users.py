import re

from config import *
from config.cluster import cluster
from models.tables import TableSearchHelper
from models.forms.users import UserProfile
from pydantic import ValidationError
from quart import Blueprint, current_app as app, render_template, request
from tools.users import Users
from utils import wrappers
from utils.helpers import batch, ensure_list
from web.helpers import render_or_json, trigger_notification, validation_error


blueprint = Blueprint("users", __name__, url_prefix="/system/users")


@blueprint.context_processor
def load_schemas():
    return {
        "_user_profile_schema": UserProfile.model_json_schema(),
    }


@blueprint.route("/<user_id>")
@wrappers.acl("system")
async def get_user(user_id: str):
    try:
        async with Users.user(id=user_id, cluster=cluster) as u:
            user = u.get()
    except ValidationError as e:
        return validation_error(e.errors())

    return await render_or_json(
        "system/includes/users/row.html", request.headers, user=user.dict()
    )


@blueprint.route("/")
@blueprint.route("/search", methods=["POST"])
@wrappers.acl("system")
async def get_users():
    try:
        search_model, page, page_size, sort_attr, sort_reverse = TableSearchHelper(
            request.form_parsed, "users", default_sort_attr="login"
        )
    except ValidationError as e:
        return validation_error(e.errors())

    if request.method == "POST":
        matched_users = [m.dict() for m in await Users().search(q=search_model.q)]

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
        user_id = request.form_parsed.get("id")

    try:
        user_ids = ensure_list(user_id)
        for user_id in user_ids:
            async with Users.user(id=user_id, cluster=cluster) as u:
                await u.delete()

    except ValidationError as e:
        return validation_error(e.errors())

    return trigger_notification(
        level="success",
        response_body="",
        response_code=204,
        title="User removed",
        message=f"{len(user_ids)} user{'s' if len(user_ids) > 1 else ''} removed",
    )


@blueprint.route("/<user_id>/credential/<hex_id>", methods=["PATCH"])
@wrappers.acl("system")
async def patch_user_credential(user_id: str, hex_id: str):
    try:
        async with Users.user(id=user_id, cluster=cluster) as u:
            doc_id = await u.patch.credential(
                hex_id=hex_id,
                data=request.form_parsed,
            )

        if not doc_id:
            return trigger_notification(
                level="error",
                response_body="",
                response_code=409,
                title="Credential error",
                message="No such credential",
            )

    except ValidationError as e:
        return validation_error(e.errors())

    return trigger_notification(
        level="success",
        response_body="",
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

        async with Users.user(id=user_id, cluster=cluster) as u:
            await u.patch(data=request.form_parsed)
            await u.patch.profile(data=request.form_parsed.get("profile", {}))

    except ValidationError as e:
        return validation_error(e.errors())

    app.config["SESSION_VALIDATED"].discard(user_id)

    return trigger_notification(
        level="success",
        response_body="",
        response_code=204,
        title="User modified",
        message=f"User was updated",
    )
