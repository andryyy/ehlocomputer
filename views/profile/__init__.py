import json
from pydantic import ValidationError
from quart import render_template, request, session, Blueprint

from config import defaults
from config.database import *
from utils import helpers
from models import profile as profile_model
from models import auth as auth_model


profile = Blueprint("profile", __name__, url_prefix="/profile")


@profile.route("/credential/<credential_id>", methods=["DELETE"])
@helpers.user_session_required
async def delete_credential(credential_id: str):
    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        users = db.table("users")
        credentials = db.table("credentials")
        user = users.search(
            (Query().id == session["id"]) & (Query().credentials.exists())
        ).pop()

        if credential_id not in user["credentials"]:
            return helpers.show_alert(
                "genericError",
                "",
                409,
                "Credential error",
                "No such credential in user realm",
            )

        if len(user["credentials"]) == 1:
            return helpers.show_alert(
                "genericError",
                "",
                409,
                "Credential error",
                "Cannot delete last key in user realm",
            )

        user["credentials"].remove(credential_id)
        users.update({"credentials": user["credentials"]}, Query().id == session["id"])
        credentials.remove(Query().id == credential_id)

    return helpers.show_alert(
        "genericSuccess",
        "",
        204,
        "Token removed",
        "The selected token was removed from your profile",
    )


@profile.route("/credential/<credential_id>", methods=["PATCH"])
@helpers.user_session_required
async def patch_credential(credential_id: str):
    req_body_dict = await request.json

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        users = db.table("users")
        credentials = db.table("credentials")
        user = users.search(
            (Query().id == session["id"]) & (Query().credentials.exists())
        ).pop()

        if credential_id not in user["credentials"]:
            return helpers.show_alert(
                "genericError",
                "",
                409,
                "Credential error",
                "No such credential in user realm",
            )

        credentials.update(
            {"friendly_name": req_body_dict.get("friendly_name")},
            Query().id == credential_id,
        )
        credential = credentials.search(Query().id == credential_id).pop()[
            "friendly_name"
        ]

    return helpers.show_alert(
        "genericSuccess", credential, 204, "Success", "Changed credential name"
    )


@profile.route("/", methods=["GET"])
@helpers.user_session_required
async def user_profile_get():
    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        users = db.table("users")
        credentials = db.table("credentials")

        user = users.search(Query().id == session["id"]).pop()
        credentials = credentials.search(Query().id.one_of(user["credentials"]))

        template = await render_template(
            "profile/profile.html",
            user_data={
                "user": user,
                "credentials": [
                    auth_model.GetCredential.parse_obj(c) for c in credentials
                ],
            },
        )

    return template


@profile.route("/<user_id>/edit", methods=["PATCH"])
@helpers.user_session_required
async def user_profile_patch(user_id: str):
    req_body_dict = await request.json
    try:
        PatchUserModel = profile_model.PatchUser.parse_obj(req_body_dict)
    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        users = db.table("users")
        users.update({"profile": PatchUserModel.dict()}, Query().id == session["id"])

    # Reloading profile into session
    session.pop("profile", None)
    session["profile"] = PatchUserModel.dict()

    return helpers.show_alert(
        "genericSuccess", "", 204, "Profile updated", "Your profile was updated"
    )
