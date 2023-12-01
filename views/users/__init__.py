import json
import sys
import traceback

from . import tools as users_helpers
from config import defaults, settings
from config.database import *
from models import users as users_model
from pydantic import ValidationError
from quart import Blueprint, render_template, request, session
from utils import helpers
from uuid import uuid4


users = Blueprint("users", __name__, url_prefix="/users")


@users.route("/")
@users.route("/search", methods=["POST"])
@helpers.user_session_required
async def get_users(user_type: str):
    req_body_dict = await request.json
    chunk = 1
    page_size = defaults.TABLE_PAGE_SIZE

    if req_body_dict and req_body_dict.get("chunk"):
        session[f"{user_type}_chunk"] = int(req_body_dict.get("chunk"))
    if req_body_dict and req_body_dict.get("page_size"):
        session[f"{user_type}_page_size"] = int(req_body_dict.get("page_size"))
    if f"{user_type}_chunk" in session:
        chunk = session[f"{user_type}_chunk"]
    if f"{user_type}_page_size" in session:
        page_size = session[f"{user_type}_page_size"]

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        user_table = db.table(user_type)
        if request.method == "POST":
            try:
                UserSearchModel = users_model.UserSearch.parse_obj(req_body_dict)
            except ValidationError as e:
                return helpers.validation_error(e.errors())
            _users = user_table.search(Query().name.search(UserSearchModel.q))
        else:
            _users = user_table.all()

        user_chunks = [m for m in helpers.batch(_users, page_size)]

        try:
            user_chunks[chunk - 1]
        except IndexError:
            chunk = len(user_chunks)

        users = user_chunks[chunk - 1] if chunk else user_chunks

        if request.method == "POST":
            tpl = f"users/partials/users_table_body.html"
        else:
            tpl = f"users/user.html"

        template = await render_template(
            tpl,
            data={
                "users": users,
                "user_type": user_type,
                "page_size": page_size,
                "chunk": chunk,
                "chunks": len(user_chunks) + 1,
                "elements": len(_users),
            },
        )
    return template


@users.route("/<user>", methods=["POST"])
@helpers.user_session_required
async def create_user(user_type: str):
    req_body_dict = await request.json

    try:
        req_body_dict.update(
            {
                "id": str(uuid4()),  # Generating user_id
            }
        )

        match user_type:
            case "domains":
                UserCreateModel = users_model.UserCreateDomain.parse_obj(req_body_dict)
            case "recipients":
                UserCreateModel = users_model.UserCreateRecipient.parse_obj(
                    req_body_dict
                )
            case "settings":
                UserCreateModel = users_model.UserCreateSetting.parse_obj(req_body_dict)

        if users_helpers.get_user_by_name(
            user_type=user_type,
            name=UserCreateModel.name,
            realm_path=request.realm_data.get("path"),
        ):
            return helpers.validation_error(
                [{"loc": ["name"], "msg": f"User name exists"}]
            )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        user_table = db.table(user_type)
        user_table.insert(UserCreateModel.dict())

    return helpers.show_alert(
        "genericSuccess", "", 204, "User created", "User was created"
    )


@users.route("/delete", methods=["POST"])
@users.route("/<user>", methods=["DELETE"])
async def delete_user(user_type: str, user_id: str | None = None):
    req_body_dict = await request.json
    try:
        if request.method == "DELETE" and user_id:
            req_body_dict.update({"user_id": user_id})

        UserDeleteModel = users_model.UserDelete.parse_obj(req_body_dict)
        for user_id in UserDeleteModel.id:
            if not users_helpers.get_user_by_id(
                user_type=user_type,
                user_id=user_id,
                realm_path=request.realm_data.get("path"),
            ):
                return helpers.validation_error(
                    [{"loc": ["id"], "msg": f"User ID {user_id} does not exist"}]
                )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        user_table = db.table(user_type)
        users = user_table.search(Query().id.one_of(UserDeleteModel.id))
        user_table.remove(doc_ids=[o.doc_id for o in users])

    return helpers.show_alert(
        "genericSuccess",
        "",
        204,
        "User removed",
        f"User{'s' if len(UserDeleteModel.id)>1 else ''} removed",
    )


@users.route("/patch", methods=["POST"])
@users.route("/<user>", methods=["PATCH"])
async def patch_user(user_type: str, user_id: str | None = None):
    req_body_dict = await request.json
    try:
        if request.method == "PATCH" and user_id:
            req_body_dict.update({"id": user_id})

        match user_type:
            case "domains":
                UserPatchModel = users_model.UserPatchDomains.parse_obj(req_body_dict)
            case "recipients":
                UserPatchModel = users_model.UserPatchRecipients.parse_obj(
                    req_body_dict
                )
            case "settings":
                UserPatchModel = users_model.UserPatchSettings.parse_obj(req_body_dict)

        # name must be unique within type
        if UserPatchModel.name:
            if len(UserPatchModel.id) > 1:
                return helpers.validation_error(
                    [
                        {
                            "loc": ["name"],
                            "msg": "Unique attribute cannot be set for multiple users",
                        }
                    ]
                )

            user_by_name = users_helpers.get_user_by_name(
                user_type=user_type,
                name=UserPatchModel.name,
                realm_path=request.realm_data.get("path"),
            )
            if user_by_name and user_by_name["id"] != UserPatchModel.id[0]:
                return helpers.validation_error(
                    [{"loc": ["name"], "msg": "User name exists"}]
                )

        for user_id in UserPatchModel.id:
            if not users_helpers.get_user_by_id(
                user_type=user_type,
                user_id=user_id,
                realm_path=request.realm_data.get("path"),
            ):
                return helpers.validation_error(
                    [{"loc": ["id"], "msg": f"User ID {user_id} does not exist"}]
                )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        user_table = db.table(user_type)
        # Update user and exclude static fields
        user_table.update(
            UserPatchModel.dict(exclude_none=True, exclude_unset=True, exclude={"id"}),
            Query().id.one_of(UserPatchModel.id),
        )

        return helpers.show_alert(
            "genericSuccess",
            "",
            204,
            "User modified",
            "User was successfully modified",
        )
