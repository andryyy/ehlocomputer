from config import *
from config.cluster import cluster
from models.auth import CredentialRead, CredentialPatch
from models.users import UserProfile, UserPatch
from pydantic import ValidationError, validate_call
from quart import (
    Blueprint,
    redirect,
    url_for,
    current_app as app,
    render_template,
    request,
    session,
    websocket,
)
from tools.users import Users
from utils import wrappers
from utils.datetimes import utc_now_as_str
from web.helpers import trigger_notification, validation_error, session_clear

blueprint = Blueprint("profile", __name__, url_prefix="/profile")


@blueprint.context_processor
def load_schemas():
    return {
        "_user_profile_schema": UserProfile.model_json_schema(),
    }


@blueprint.route("/")
@wrappers.acl("any")
async def user_profile_get():
    try:
        async with Users.user(id=session["id"], cluster=cluster) as u:
            user = u.get()
        async with Users.create(cluster=cluster) as c:
            await c.credential(data={"login": "asdsasdada"})
    except ValidationError:
        session_clear()
        return redirect(url_for("root.root"))

    return await render_template(
        "profile/profile.html",
        data={
            "user": user.dict(),
            "keypair": None,
            "credentials": user.credentials,
        },
    )


@blueprint.route("/edit", methods=["PATCH"])
@wrappers.acl("any")
async def user_profile_patch():
    try:
        async with Users.user(id=session["id"], cluster=cluster) as u:
            await u.patch.profile(data=request.form_parsed)
            await u.refresh()
            user = u.get()

    except ValidationError as e:
        return validation_error(e.errors())

    session.pop("profile", None)
    session["profile"] = user.profile.dict()

    return trigger_notification(
        level="success",
        response_body="",
        response_code=204,
        title="Profile updated",
        message="Your profile was updated",
    )


@blueprint.route("/credential/<credential_hex_id>", methods=["PATCH"])
@wrappers.acl("any")
async def patch_credential(credential_hex_id: str):
    try:
        async with Users.user(id=session["id"], cluster=cluster) as u:
            await u.patch.credential(
                hex_id=credential_hex_id,
                data=request.form_parsed,
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


@blueprint.route("/credential/<credential_hex_id>", methods=["DELETE"])
@wrappers.acl("any")
async def delete_credential(credential_hex_id: str):
    try:
        user_instance = Users.user(id=session["id"])
        async with user_instance.Delete as delete:
            await delete.credential(hex_id=credential_hex_id)
    except ValidationError as e:
        return validation_error(e.errors())

    return trigger_notification(
        level="success",
        response_body="",
        response_code=204,
        title="Credential deleted",
        message="Credential was removed",
    )
