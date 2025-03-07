import components.users

from components.models.users import UserProfile
from components.web.utils import *

blueprint = Blueprint("profile", __name__, url_prefix="/profile")


@blueprint.context_processor
def load_context():
    context = dict()
    context["schemas"] = {"user_profile": UserProfile.model_json_schema()}
    return context


@blueprint.route("/")
@acl("any")
async def user_profile_get():
    try:
        user = await components.users.get(user_id=session["id"])
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
@acl("any")
async def user_profile_patch():
    try:
        async with ClusterLock("users", current_app):
            await components.users.patch_profile(
                user_id=session["id"], data=request.form_parsed
            )

        user = await components.users.get(user_id=session["id"])

    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    session.pop("profile", None)
    session["profile"] = user.profile.dict()

    return trigger_notification(
        level="success",
        response_code=204,
        title="Profile updated",
        message="Your profile was updated",
    )


@blueprint.route("/credential/<credential_hex_id>", methods=["PATCH"])
@acl("any")
async def patch_credential(credential_hex_id: str):
    try:
        async with ClusterLock("credentials", current_app):
            await components.users.patch_credential(
                user_id=session["id"],
                hex_id=credential_hex_id,
                data=request.form_parsed,
            )
    except ValidationError as e:
        return validation_error(e.errors())

    return trigger_notification(
        level="success",
        response_code=204,
        title="Credential modified",
        message="Credential was modified",
    )


@blueprint.route("/credential/<credential_hex_id>", methods=["DELETE"])
@acl("any")
async def delete_credential(credential_hex_id: str):
    try:
        async with ClusterLock(["credentials", "users"], current_app):
            await components.users.delete_credential(
                user_id=session["id"], hex_id=credential_hex_id
            )
    except ValidationError as e:
        return validation_error(e.errors())

    return trigger_notification(
        level="success",
        response_code=204,
        title="Credential deleted",
        message="Credential was removed",
    )
