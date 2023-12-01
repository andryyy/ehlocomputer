import json
import qrcode
import qrcode.image.svg
import sys

from . import tools as auth_helpers
from base64 import b64decode, b64encode
from config import defaults, logger
from config.database import *
from models import auth as auth_model
from models import users as users_model
from pydantic import ValidationError
from quart import (
    Blueprint,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from secrets import token_urlsafe
from utils import helpers
from uuid import uuid4
from webauthn import (
    generate_registration_options,
    options_to_json,
    verify_registration_response,
    verify_authentication_response,
    generate_authentication_options,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    RegistrationCredential,
    AuthenticationCredential,
)

auth = Blueprint("auth", __name__, url_prefix="/auth")


@auth.route("/proxy/start", methods=["POST"])
async def proxy_auth_start():
    req_body_dict = await request.json
    realm_origin = request.realm_data.get("origin")

    try:
        AuthenticationModel = auth_model.Authentication.parse_obj(req_body_dict)
    except ValidationError as e:
        return helpers.validation_error(e.errors())

    session.clear()
    proxy_auth_id = str(uuid4())

    r.set(
        proxy_auth_id,
        f"{AuthenticationModel.login}:awaiting",
        ex=defaults.PROXY_AUTH_TIMEOUT,
    )

    qr = qrcode.QRCode(
        image_factory=qrcode.image.svg.SvgPathImage,
        box_size=15,
        border=4,
    )

    qr.add_data(f"https://{realm_origin}/auth/proxy/confirm/{proxy_auth_id}")
    qr.make()
    qr_img = qr.make_image(attrib={"class": "qr-code"})

    return await render_template(
        "auth/proxy/partials/authentication_modal.html",
        data={
            "qr": qr_img.to_string(encoding="unicode"),
            "proxy_auth_id": proxy_auth_id,
        },
    )


@auth.route("/proxy/await/<proxy_auth_id>")
async def proxy_auth_get(proxy_auth_id: str = ""):
    proxy_auth = r.get(proxy_auth_id)
    if proxy_auth:
        if proxy_auth.endswith(":verified") and proxy_auth != ":verified":
            with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
                users = db.table("users")
                user = users.get(Query().login == proxy_auth.removesuffix(":verified"))

            session["login"] = proxy_auth.removesuffix(":verified")
            session["id"] = user["id"]

            r.delete(proxy_auth_id)
        else:
            abort(403)

    return "", 200, {"HX-Redirect": "/"}


@auth.route("/token", methods=["POST"])
async def token_authentication():
    req_body_dict = await request.json
    try:
        PreTokenAuthenticationModel = auth_model.PreTokenAuthentication.parse_obj(
            req_body_dict
        )
        if r.hget(PreTokenAuthenticationModel.token, "status") != "awaiting_intention":
            return helpers.validation_error(
                [
                    {
                        "loc": ["token"],
                        "msg": f"Token status is invalid",
                    }
                ]
            )

        r.hset(
            PreTokenAuthenticationModel.token,
            "intention",
            f"Authenticate user {PreTokenAuthenticationModel.login}",
        )
        r.hset(PreTokenAuthenticationModel.token, "status", "awaiting_confirmation")

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    template = await render_template(
        "auth/partials/login_form_token_confirm.html",
        data={
            "login": PreTokenAuthenticationModel.login,
            "token": PreTokenAuthenticationModel.token,
        },
    )
    return template


@auth.route("/token/verification", methods=["POST"])
async def token_authentication_verify():
    req_body_dict = await request.json
    try:
        TokenAuthenticationModel = auth_model.TokenAuthentication.parse_obj(
            req_body_dict
        )

        token_status = r.hget(TokenAuthenticationModel.token, "status")
        token_confirmation_code = r.hget(
            TokenAuthenticationModel.token, "confirmation_code"
        )

        r.delete(TokenAuthenticationModel.token)

        if token_status != "confirmed" or token_confirmation_code != str(
            TokenAuthenticationModel.confirmation_code
        ):
            return helpers.validation_error(
                [
                    {
                        "loc": ["confirmation_code"],
                        "msg": "Confirmation code is invalid",
                    }
                ]
            )

        user = auth_helpers.get_user_by_login(
            login=TokenAuthenticationModel.login,
            realm_path=request.realm_data.get("path"),
        )

        if not user:
            return helpers.show_alert(
                "genericError",
                "",
                409,
                "Authentication failed",
                "Something went wrong, please try again",
            )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    session["login"] = TokenAuthenticationModel.login
    session["id"] = user["id"]
    session["cred_id"] = None
    session["realm_id"] = request.realm_data.get("id")
    session["lang"] = request.accept_languages.best_match(defaults.ACCEPT_LANGUAGES)

    # Read profile from db to session if exists
    if user.get("profile"):
        session["profile"] = user["profile"]

    return "", 200, {"HX-Redirect": "/profile"}


@auth.route("/proxy/confirm/<proxy_auth_id>")
async def proxy_auth_confirm_get(proxy_auth_id: str = ""):
    proxy_auth = r.get(proxy_auth_id)
    if proxy_auth and proxy_auth.endswith(":awaiting"):
        session["proxy_auth_id"] = proxy_auth_id
        template = await render_template(
            "auth/proxy/confirm_authentication.html",
            login=proxy_auth.removesuffix(":awaiting"),
        )
        return template

    session["proxy_auth_id"] = None
    return redirect(url_for("root"))


@auth.route("/generate-authentication-options", methods=["POST"])
async def auth_generate_auth_opts():
    req_body_dict = await request.json
    try:
        AuthenticationModel = auth_model.Authentication.parse_obj(req_body_dict)
        user = auth_helpers.get_user_by_login(
            login=AuthenticationModel.login,
            realm_path=request.realm_data.get("path"),
        )
        user_credentials = auth_helpers.get_user_credentials_by_login(
            login=AuthenticationModel.login,
            realm_path=request.realm_data.get("path"),
        )
        if not user or not user_credentials:
            return helpers.validation_error(
                [{"loc": ["login"], "msg": f"User is not available"}]
            )
    except ValidationError as e:
        return helpers.validation_error(e.errors())

    options = generate_authentication_options(
        rp_id=request.realm_data.get("origin"),
        timeout=defaults.WEBAUTHN_CHALLENGE_TIMEOUT * 1000,
        allow_credentials=[
            auth_model.GetCredential.parse_obj(c).dict() for c in user_credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    session["auth_challenge_id"] = str(uuid4())
    r.set(
        session["auth_challenge_id"],
        b64encode(options.challenge),
        ex=defaults.WEBAUTHN_CHALLENGE_TIMEOUT,
    )

    # 204 prevents swap
    return "", 204, {"HX-Trigger": json.dumps({"startAuth": options_to_json(options)})}


@auth.route("/pre-registration", methods=["POST"])
async def auth_pre_registration():
    req_body_dict = await request.json
    try:
        PreRegistrationModel = auth_model.PreRegistration.parse_obj(req_body_dict)
        if r.hget(PreRegistrationModel.token, "status") != "awaiting_intention":
            return helpers.validation_error(
                [
                    {
                        "loc": ["token"],
                        "msg": f"Token status is invalid",
                    }
                ]
            )

        r.hset(
            PreRegistrationModel.token,
            "intention",
            f"Client {request.headers}: Register user {PreRegistrationModel.login}",
        )
        r.hset(PreRegistrationModel.token, "status", "awaiting_confirmation")

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    template = await render_template(
        "auth/partials/register_form_token_confirm.html",
        data={
            "login": PreRegistrationModel.login,
            "token": PreRegistrationModel.token,
        },
    )
    return template


@auth.route("/generate-registration-options", methods=["POST"])
async def auth_generate_reg_opts():
    req_body_dict = await request.json
    try:
        RegistrationModel = auth_model.Registration.parse_obj(req_body_dict)
        token_status = r.hget(RegistrationModel.token, "status")
        token_confirmation_code = r.hget(RegistrationModel.token, "confirmation_code")

        r.delete(RegistrationModel.token)

        if token_status != "confirmed" or token_confirmation_code != str(
            RegistrationModel.confirmation_code
        ):
            return helpers.validation_error(
                [
                    {
                        "loc": ["confirmation_code"],
                        "msg": "Confirmation code is invalid",
                    }
                ]
            )
    except ValidationError as e:
        return helpers.validation_error(e.errors())

    user = auth_helpers.get_user_by_login(
        login=RegistrationModel.login,
        realm_path=request.realm_data.get("path"),
    )

    if session.get("login") == RegistrationModel.login:
        # We want to add a token for an existing user
        exclude_credentials = auth_helpers.get_user_credentials_by_login(
            login=RegistrationModel.login,
            realm_path=request.realm_data.get("path"),
        )
        user_id = user["id"]
    elif not user:
        # We want to create a new user
        exclude_credentials = []
        user_id = str(uuid4())
    else:
        return helpers.show_alert(
            "genericError", "", 409, "Registration failed", "This username is reserved"
        )

    options = generate_registration_options(
        rp_name=request.realm_data.get("name"),
        rp_id=request.realm_data.get("origin"),
        user_id=user_id,
        timeout=defaults.WEBAUTHN_CHALLENGE_TIMEOUT * 1000,
        exclude_credentials=[
            auth_model.GetCredential.parse_obj(c).dict() for c in exclude_credentials
        ],
        user_name=RegistrationModel.login,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
    )
    session["registration_challenge_user_id"] = user_id
    r.set(
        session["registration_challenge_user_id"],
        b64encode(options.challenge),
        ex=defaults.WEBAUTHN_CHALLENGE_TIMEOUT,
    )

    # 204 prevents swap
    return "", 204, {"HX-Trigger": json.dumps({"startReg": options_to_json(options)})}


@auth.route("/verify-registration-response", methods=["POST"])
async def auth_register_verify():
    req_body_dict = await request.json
    req_body_raw = await request.data
    try:
        RegistrationModel = auth_model.Registration.parse_obj(req_body_dict)
        if not session.get("registration_challenge_user_id") or not r.exists(
            session["registration_challenge_user_id"]
        ):
            return helpers.show_alert(
                "genericError",
                "",
                409,
                "Registration session invalid",
                "Please restart the registration process",
            )
    except ValidationError as e:
        return helpers.validation_error(e.errors())

    registration_challenge = b64decode(
        r.getdel(session["registration_challenge_user_id"])
    )

    try:
        current_challenge = registration_challenge
        user_id = session["registration_challenge_user_id"]
        credential = RegistrationCredential.parse_raw(req_body_raw)
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=current_challenge,
            expected_rp_id=request.realm_data.get("origin"),
            expected_origin=f"https://{request.realm_data.get('origin')}",
            require_user_verification=True,
        )
    except Exception as e:
        logger.error(e)
        return helpers.show_alert(
            "genericError",
            "",
            409,
            "Registration failed",
            "An error occured verifying the registration",
        )

    AddCredentialModel = auth_model.AddCredential.parse_obj(
        {
            "id": verification.credential_id,
            "public_key": verification.credential_public_key,
            "sign_count": verification.sign_count,
            "friendly_name": "Keyanu Reeves",
            "transports": req_body_dict.get("transports", []),
        }
    )

    session["registration_challenge_user_id"] = None

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        user = db.table("users").get(Query().login == RegistrationModel.login)

    try:
        if session.get("id") == user_id:
            user["credentials"].append(AddCredentialModel.id)
            users.update({"credentials": user["credentials"]}, Query().id == user_id)
        elif not user:
            with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
                AddUserModel = users_model.AddUser(
                    id=user_id,
                    login=RegistrationModel.login,
                    credentials=[verification.credential_id],
                )
                db.table("users").insert(AddUserModel.dict())
        else:
            raise Exception("Lost track in registration process")

        with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
            db.table("credentials").upsert(
                AddCredentialModel.dict(), Query().id == AddCredentialModel.id
            )

    except Exception as e:
        exception = sys.exc_info()
        logger.opt(exception=exception).info("Logging exception traceback")
        return helpers.show_alert(
            "genericError",
            "",
            409,
            "Registration failed",
            "An error occured verifying the registration",
        )

    if user:
        return helpers.show_alert(
            "genericSuccess",
            "",
            204,
            "New token registered",
            "A new token was appended to your account and can now be used to login",
        )

    return helpers.show_alert(
        "genericSuccess",
        "",
        204,
        "Welcome on board 👋",
        "Your account was created, you can now login",
    )


@auth.route("/verify-authentication-response", methods=["POST"])
async def auth_login_verify():
    req_body_dict = await request.json
    req_body_raw = await request.data

    try:
        auth_challenge = b64decode(r.get(session["auth_challenge_id"]))
        credential = AuthenticationCredential.parse_raw(req_body_raw)
        user = auth_helpers.get_user_by_id(
            user_id=b64decode(credential.response.user_handle).decode("utf-8"),
            realm_path=request.realm_data.get("path"),
        )

        if not user or not credential.raw_id.hex() in user["credentials"]:
            return helpers.show_alert(
                "genericError",
                "",
                409,
                "Verification failed",
                "No such credential in user realm",
            )

        user_credentials = auth_helpers.get_user_credentials_by_login(
            login=user["login"],
            realm_path=request.realm_data.get("path"),
        )
        user_login_credential = auth_model.GetCredential.parse_obj(
            next(filter(lambda c: c["id"] == credential.raw_id.hex(), user_credentials))
        )
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=auth_challenge,
            expected_rp_id=request.realm_data.get("origin"),
            expected_origin=f"https://{request.realm_data.get('origin')}",
            credential_public_key=user_login_credential.public_key,
            credential_current_sign_count=user_login_credential.sign_count,
            require_user_verification=True,
        )

        with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
            credentials = db.table("credentials")
            if user_login_credential.sign_count != 0:
                credentials.update(
                    {"sign_count": verification.new_sign_count},
                    Query().id == credential.raw_id.hex(),
                )
            credentials.update(
                {"last_login": helpers.utc_now_as_str()},
                Query().id == credential.raw_id.hex(),
            )

    except Exception as e:
        logger.error(e)
        return helpers.show_alert(
            "genericError",
            "",
            409,
            "Verification failed",
            "An error occured verifying the credential",
        )

    proxy_auth_id = session.get("proxy_auth_id")
    if proxy_auth_id:
        proxy_auth = r.get(proxy_auth_id)
        """
        Not setting session login and id for device that is confirming the proxy authentication
        Gracing 10s for the awaiting party to catch up an almost expired key
        """
        r.set(proxy_auth_id, f"{user['login']}:verified", ex=10)
        session["proxy_auth_id"] = None
        return "", 204, {"HX-Trigger": "proxyAuthSuccess"}

    """
        login: Username as str
        id: User UUID as str
        cred_id: Credential ID as hex string
        profile: User profile as dict
    """

    session["login"] = req_body_dict["login"]
    session["id"] = b64decode(credential.response.user_handle).decode()
    session["cred_id"] = credential.raw_id.hex()
    session["realm_id"] = request.realm_data.get("id")
    session["lang"] = request.accept_languages.best_match(defaults.ACCEPT_LANGUAGES)

    # Read profile from db to session if exists
    if user.get("profile"):
        session["profile"] = user["profile"]

    return "", 200, {"HX-Redirect": "/profile"}
