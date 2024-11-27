from config.cluster import ClusterLock
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
    from models.users import UserProfile

    return {
        "_user_profile_schema": UserProfile.model_json_schema(),
    }


@blueprint.route("/")
@wrappers.acl("any")
async def user_profile_get():
    try:
        user = await Users.user(id=session["id"]).get()
    except ValidationError:
        session_clear()
        return redirect(url_for("root.root"))
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

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
        async with ClusterLock("main"):
            await Users.user(id=session["id"]).patch_profile(data=request.form_parsed)

        user = await Users.user(id=session["id"]).get()

    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

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
        async with ClusterLock("main"):
            await Users.user(id=session["id"]).patch_credential(
                hex_id=credential_hex_id, data=request.form_parsed
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
        await Users.user(id=session["id"]).delete_credential(hex_id=credential_hex_id)
    except ValidationError as e:
        return validation_error(e.errors())

    return trigger_notification(
        level="success",
        response_body="",
        response_code=204,
        title="Credential deleted",
        message="Credential was removed",
    )
