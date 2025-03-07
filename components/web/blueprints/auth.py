import asyncio
import json

from base64 import b64decode, b64encode
from components.models.users import (
    UserSession,
    AuthToken,
    TokenConfirmation,
    TypeAdapter,
    uuid4,
)
from components.web.utils import *
from secrets import token_urlsafe
from components.utils import expire_key
from components.utils.datetimes import utc_now_as_str
from components.users import (
    get as get_user,
    what_id,
    patch_credential,
    create as create_user,
    create_credential,
)
from webauthn import (
    generate_registration_options,
    options_to_json,
    verify_registration_response,
    verify_authentication_response,
    generate_authentication_options,
)
from webauthn.helpers import (
    parse_registration_credential_json,
    parse_authentication_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AttestationConveyancePreference,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
)

blueprint = Blueprint("auth", __name__, url_prefix="/auth")


# A link to be sent to a user to login using webauthn authentication
# /auth/login/request/confirm/<request_token>
@blueprint.route("/login/request/confirm/<request_token>")
async def login_request_confirm(request_token: str):
    try:
        TypeAdapter(str).validate_python(request_token)
    except:
        return "", 200, {"HX-Redirect": "/"}

    token_status = IN_MEMORY_DB.get(request_token, {}).get("status")

    if token_status == "awaiting":
        session["request_token"] = request_token
        requested_login = IN_MEMORY_DB[request_token]["requested_login"]

        return await render_template(
            "auth/login/request/confirm.html",
            login=requested_login,
        )

    session["request_token"] = None

    return "", 200, {"HX-Redirect": "/profile", "HX-Refresh": False}


@blueprint.route("/register/request/confirm/<login>", methods=["POST", "GET"])
@acl("system")
async def register_request_confirm_modal(login: str):
    return await render_template("auth/register/request/confirm.html")


# As shown to user that is currently logged in
# /auth/login/request/confirm/modal/<request_token>
@blueprint.route(
    "/login/request/confirm/internal/<request_token>", methods=["POST", "GET"]
)
@acl("any")
async def login_request_confirm_modal(request_token: str):
    try:
        TypeAdapter(str).validate_python(request_token)
    except:
        return "", 204

    if request.method == "POST":
        if (
            request_token in IN_MEMORY_DB
            and IN_MEMORY_DB[request_token]["status"] == "awaiting"
        ):
            IN_MEMORY_DB[request_token].update(
                {
                    "status": "confirmed",
                    "credential_id": "",
                }
            )
            current_app.add_background_task(
                expire_key,
                IN_MEMORY_DB,
                request_token,
                10,
            )

            await ws_htmx(session["login"], "delete:#auth-login-request", "")

            return "", 204

        return trigger_notification(
            level="warning",
            response_code=403,
            title="Confirmation failed",
            message="Token denied",
        )

    return await render_template("auth/login/request/internal/confirm.html")


# An unknown user issues a login request to users that are currently logged in
# /auth/login/request/start
@blueprint.route("/login/request/start", methods=["POST"])
async def login_request_start():
    try:
        request_data = AuthToken.parse_obj(request.form_parsed)
    except ValidationError as e:
        return validation_error(e.errors())

    session_clear()

    try:
        user_id = await what_id(login=request_data.login)
        user = await get_user(user_id=user_id)
    except (ValidationError, ValueError):
        return validation_error([{"loc": ["login"], "msg": f"User is not available"}])

    request_token = token_urlsafe()

    IN_MEMORY_DB[request_token] = {
        "intention": f"Authenticate user: {request_data.login}",
        "status": "awaiting",
        "token_type": "web_confirmation",
        "requested_login": request_data.login,
    }

    current_app.add_background_task(
        expire_key,
        IN_MEMORY_DB,
        request_token,
        defaults.AUTH_REQUEST_TIMEOUT,
    )

    if user.profile.permit_auth_requests:
        await ws_htmx(
            request_data.login,
            "beforeend",
            f'<div id="auth-permit" hx-trigger="load" hx-get="/auth/login/request/confirm/internal/{request_token}"></div>',
        )

    return await render_template(
        "auth/login/request/start.html",
        data={
            "request_token": request_token,
            "request_issued_to_user": user.profile.permit_auth_requests,
        },
    )


# Polled every second by unknown user that issued a login request
# /auth/login/request/check/<request_token>
@blueprint.route("/login/request/check/<request_token>")
async def login_request_check(request_token: str):
    try:
        TypeAdapter(str).validate_python(request_token)
    except:
        session.clear()
        return "", 200, {"HX-Redirect": "/"}

    token_status, requested_login, credential_id = map(
        IN_MEMORY_DB.get(request_token, {}).get,
        ["status", "requested_login", "credential_id"],
    )

    if token_status == "confirmed":
        try:
            user_id = await what_id(login=requested_login)
            user = await get_user(user_id=user_id)
        except ValidationError as e:
            return validation_error(
                [{"loc": ["login"], "msg": f"User is not available"}]
            )

        for k, v in (
            UserSession(
                login=user.login,
                id=user.id,
                acl=user.acl,
                cred_id=credential_id,
                lang=request.accept_languages.best_match(defaults.ACCEPT_LANGUAGES),
                profile=user.profile,
            )
            .dict()
            .items()
        ):
            session[k] = v

    else:
        if token_status:
            return "", 204

    return "", 200, {"HX-Redirect": "/"}


@blueprint.route("/login/token", methods=["POST"])
async def login_token():
    try:
        request_data = AuthToken.parse_obj(request.form_parsed)
        token = request_data.token
        IN_MEMORY_DB[token] = {
            "intention": f"Authenticate user: {request_data.login}",
            "status": "awaiting",
            "token_type": "cli_confirmation",
            "login": request_data.login,
        }
        current_app.add_background_task(
            expire_key,
            IN_MEMORY_DB,
            token,
            120,
        )

    except ValidationError as e:
        return validation_error(e.errors())

    return await render_template(
        "auth/login/token.html",
        token=token,
    )


@blueprint.route("/login/token/verify", methods=["POST"])
async def login_token_verify():
    try:
        request_data = TokenConfirmation.parse_obj(request.form_parsed)

        token_status, token_login, token_confirmation_code = map(
            IN_MEMORY_DB.get(request_data.token, {}).get,
            ["status", "login", "code"],
        )
        IN_MEMORY_DB.pop(request_data.token, None)

        if (
            token_status != "confirmed"
            or token_confirmation_code != request_data.confirmation_code
        ):
            return validation_error(
                [
                    {
                        "loc": ["confirmation_code"],
                        "msg": "Confirmation code is invalid",
                    }
                ]
            )

        user_id = await what_id(login=token_login)
        user = await get_user(user_id=user_id)

    except ValidationError as e:
        return validation_error(e.errors())

    for k, v in (
        UserSession(
            login=token_login,
            id=user.id,
            acl=user.acl,
            lang=request.accept_languages.best_match(defaults.ACCEPT_LANGUAGES),
            profile=user.profile,
        )
        .dict()
        .items()
    ):
        session[k] = v

    return "", 200, {"HX-Redirect": "/profile", "HX-Refresh": False}


# Generate login options for webauthn authentication
@blueprint.route("/login/webauthn/options", methods=["POST"])
async def login_webauthn_options():
    try:
        user_id = await what_id(login=request.form_parsed.get("login"))
        user = await get_user(user_id=user_id)
        if not user.credentials:
            raise ValidationError
    except (ValidationError, ValueError):
        return validation_error([{"loc": ["login"], "msg": f"User is not available"}])

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=bytes.fromhex(c))
        for c in user.credentials.keys()
    ]

    options = generate_authentication_options(
        rp_id=defaults.WEBAUTHN_RP_ID,
        timeout=defaults.WEBAUTHN_CHALLENGE_TIMEOUT * 1000,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    session["webauthn_challenge_id"] = token_urlsafe()

    IN_MEMORY_DB[session["webauthn_challenge_id"]] = {
        "challenge": b64encode(options.challenge),
        "login": user.login,
    }
    current_app.add_background_task(
        expire_key,
        IN_MEMORY_DB,
        session["webauthn_challenge_id"],
        defaults.WEBAUTHN_CHALLENGE_TIMEOUT,
    )

    return "", 204, {"HX-Trigger": json.dumps({"startAuth": options_to_json(options)})}


@blueprint.route("/register/token", methods=["POST"])
async def register_token():
    try:
        request_data = AuthToken.parse_obj(request.form_parsed)
        token = request_data.token
        IN_MEMORY_DB[token] = {
            "intention": f"Register user: {request_data.login}",
            "status": "awaiting",
            "login": request_data.login,
        }
        current_app.add_background_task(
            expire_key,
            IN_MEMORY_DB,
            token,
            120,
        )
        await ws_htmx(
            "system",
            "beforeend",
            f'<div id="auth-permit" hx-trigger="load" hx-get="/auth/register/request/confirm/{request_data.login}"></div>',
        )

    except ValidationError as e:
        return validation_error(e.errors())

    return await render_template(
        "auth/register/token.html",
        token=token,
    )
    return template


@blueprint.route("/register/webauthn/options", methods=["POST"])
async def register_webauthn_options():
    if "token" in request.form_parsed:
        try:
            request_data = TokenConfirmation.parse_obj(request.form_parsed)
        except ValidationError as e:
            return validation_error(e.errors())

        token_status, token_login, token_confirmation_code = map(
            IN_MEMORY_DB.get(request_data.token, {}).get,
            ["status", "login", "code"],
        )
        IN_MEMORY_DB.pop(request_data.token, None)

        if (
            token_status != "confirmed"
            or token_confirmation_code != request_data.confirmation_code
        ):
            return validation_error(
                [
                    {
                        "loc": ["confirmation_code"],
                        "msg": "Confirmation code is invalid",
                    }
                ]
            )

        exclude_credentials = []
        user_id = str(uuid4())
        login = token_login
        appending_passkey = False
    else:
        if not session.get("id"):
            return trigger_notification(
                level="error",
                response_code=409,
                title="Registration failed",
                message="Something went wrong",
            )

        user = await get_user(user_id=session["id"])

        exclude_credentials = [
            PublicKeyCredentialDescriptor(id=bytes.fromhex(c))
            for c in user.credentials.keys()
        ]

        user_id = session["id"]
        login = session["login"]
        appending_passkey = True

    options = generate_registration_options(
        rp_name=defaults.WEBAUTHN_RP_NAME,
        rp_id=defaults.WEBAUTHN_RP_ID,
        user_id=user_id.encode("ascii"),
        timeout=defaults.WEBAUTHN_CHALLENGE_TIMEOUT * 1000,
        exclude_credentials=exclude_credentials,
        user_name=login,
        attestation=AttestationConveyancePreference.DIRECT,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
    )

    session["webauthn_challenge_id"] = token_urlsafe()

    IN_MEMORY_DB[session["webauthn_challenge_id"]] = {
        "challenge": b64encode(options.challenge),
        "login": login,
        "user_id": user_id,
        "appending_passkey": appending_passkey,
    }
    current_app.add_background_task(
        expire_key,
        IN_MEMORY_DB,
        session["webauthn_challenge_id"],
        defaults.WEBAUTHN_CHALLENGE_TIMEOUT,
    )

    return "", 204, {"HX-Trigger": json.dumps({"startReg": options_to_json(options)})}


@blueprint.route("/register/webauthn", methods=["POST"])
async def register_webauthn():
    json_body = await request.json

    webauthn_challenge_id = session.get("webauthn_challenge_id")
    session["webauthn_challenge_id"] = None

    challenge, login, user_id, appending_passkey = map(
        IN_MEMORY_DB.get(webauthn_challenge_id, {}).get,
        ["challenge", "login", "user_id", "appending_passkey"],
    )
    IN_MEMORY_DB.pop(webauthn_challenge_id, None)

    if not challenge:
        return trigger_notification(
            level="error",
            response_code=409,
            title="Registration session invalid",
            message="Registration session invalid",
            additional_triggers={"authRegFailed": "register"},
        )

    try:
        credential = parse_registration_credential_json(json_body)
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=b64decode(challenge),
            expected_rp_id=defaults.WEBAUTHN_RP_ID,
            expected_origin=f"https://{defaults.WEBAUTHN_RP_ORIGIN}",
            require_user_verification=True,
        )
    except Exception as e:
        return trigger_notification(
            level="error",
            response_code=409,
            title="Registration failed",
            message="An error occured while verifying the credential",
            additional_triggers={"authRegFailed": "register"},
        )

    credential_data = {
        "id": verification.credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
        "friendly_name": "Key Anú Reeves",
        "transports": json_body.get("transports", []),
    }

    try:
        async with ClusterLock("users", current_app):
            if not appending_passkey:
                user_id = await create_user(data={"login": login})

            await create_credential(
                user_id=user_id,
                data={
                    "id": verification.credential_id,
                    "public_key": verification.credential_public_key,
                    "sign_count": verification.sign_count,
                    "transports": json_body.get("transports", []),
                },
            )

    except Exception as e:
        return trigger_notification(
            level="error",
            response_code=409,
            title="Registration failed",
            message="An error occured verifying the registration",
            additional_triggers={"authRegFailed": "register"},
        )

    if appending_passkey:
        await ws_htmx(
            session["login"],
            "beforeend",
            f'<div id="after-cred-add" hx-sync="abort" hx-trigger="load delay:1s" hx-target="#body-main" hx-get="/profile"></div>',
        )
        return trigger_notification(
            level="success",
            response_code=204,
            title="New token registered",
            message="A new token was appended to your account and can now be used to login",
        )

    return trigger_notification(
        level="success",
        response_code=204,
        title="Welcome on board 👋",
        message="Your account was created, you can now log in",
        additional_triggers={"regCompleted": login},
    )


@blueprint.route("/login/webauthn", methods=["POST"])
async def auth_login_verify():
    json_body = await request.json

    try:
        webauthn_challenge_id = session.get("webauthn_challenge_id")
        challenge, login = map(
            IN_MEMORY_DB.get(webauthn_challenge_id, {}).get,
            ["challenge", "login"],
        )
        IN_MEMORY_DB.pop(webauthn_challenge_id, None)
        session["webauthn_challenge_id"] = None

        if not all([webauthn_challenge_id, challenge, login]):
            return trigger_notification(
                level="error",
                response_code=409,
                title="Verification failed",
                message="Verification process timed out",
                additional_triggers={"authRegFailed": "authenticate"},
            )

        auth_challenge = b64decode(challenge)

        user_id = await what_id(login=login)
        user = await get_user(user_id=user_id)

        credential = parse_authentication_credential_json(json_body)

        matched_user_credential = None
        for k, v in user.credentials.items():
            if bytes.fromhex(k) == credential.raw_id:
                matched_user_credential = v

        if not matched_user_credential:
            return trigger_notification(
                level="error",
                response_code=409,
                title="Verification failed",
                message="No such credential in user realm",
                additional_triggers={"authRegFailed": "authenticate"},
            )

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=auth_challenge,
            expected_rp_id=defaults.WEBAUTHN_RP_ORIGIN,
            expected_origin=f"https://{defaults.WEBAUTHN_RP_ORIGIN}",
            credential_public_key=matched_user_credential.public_key,
            credential_current_sign_count=matched_user_credential.sign_count,
            require_user_verification=True,
        )

        data = {"last_login": utc_now_as_str()}
        if matched_user_credential.sign_count != 0:
            data["sign_count"] = verification.new_sign_count

        async with ClusterLock("credentials", current_app):
            user_id = await what_id(login=login)
            await patch_credential(
                user_id=user_id,
                hex_id=credential.raw_id.hex(),
                data=data,
            )

    except Exception as e:
        return trigger_notification(
            level="error",
            response_code=409,
            title="Verification failed",
            message="An error occured verifying the credential",
            additional_triggers={"authRegFailed": "authenticate"},
        )

    request_token = session.get("request_token")

    if request_token:
        """
        Not setting session login and id for device that is confirming the proxy authentication
        Gracing 10s for the awaiting party to catch up an almost expired key
        """
        IN_MEMORY_DB[request_token].update(
            {
                "status": "confirmed",
                "credential_id": credential.raw_id.hex(),
            }
        )
        current_app.add_background_task(
            expire_key,
            IN_MEMORY_DB,
            request_token,
            10,
        )
        session["request_token"] = None

        return "", 204, {"HX-Trigger": "proxyAuthSuccess"}

    for k, v in (
        UserSession(
            login=user.login,
            id=user.id,
            acl=user.acl,
            cred_id=credential.raw_id.hex(),
            lang=request.accept_languages.best_match(defaults.ACCEPT_LANGUAGES),
            profile=user.profile,
        )
        .dict()
        .items()
    ):
        session[k] = v

    return "", 200, {"HX-Redirect": "/profile", "HX-Refresh": False}
