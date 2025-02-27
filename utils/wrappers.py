import asyncio
import json

from config import defaults
from config.logs import logger
from utils.cluster.cluster import cluster
from contextlib import suppress
from functools import wraps
from models.auth import UserSession
from pydantic import TypeAdapter, ValidationError, validate_call
from quart import (
    current_app as app,
    redirect,
    request,
    session,
    url_for,
    abort,
    websocket,
)
from tools.objects import search as search_object
from tools.users import get as get_user, what_id, search as search_users
from web.helpers import session_clear, trigger_notification
from typing import Literal


class AuthException(Exception):
    pass


@validate_call
async def verify_session(acl: Literal[*defaults.USER_ACLS, "any"]) -> None:
    if not session.get("id"):
        raise AuthException("Session ID missing")

    if session["id"] not in app.config["SESSION_VALIDATED"]:
        try:
            user = await get_user(user_id=session["id"])
            app.config["SESSION_VALIDATED"].update({session["id"]: user.acl})
        except:
            session_clear()
            raise AuthException("User unknown")

    if acl != "any":
        if acl not in app.config["SESSION_VALIDATED"][session["id"]]:
            raise AuthException("Access denied by ACL")


async def create_session_by_token(token):
    if len(token.split(":")) != 2:
        raise AuthException("Invalid access token format")

    token_user, token_value = token.split(":")

    try:
        TypeAdapter(defaults.ACCESS_TOKEN_FORMAT).validate_python(token_value)
    except ValidationError as e:
        raise AuthException("Invalid token format")

    try:
        user_id = await what_id(login=token_user)
        user = await get_user(user_id=user_id)
    except:
        session_clear()
        raise AuthException("User unknown")

    if token_value not in user.profile.access_tokens:
        raise AuthException("Token unknown in user context")

    user_session = UserSession(
        login=user.login,
        id=user.id,
        acl=user.acl,
        cred_id="",
        lang=request.accept_languages.best_match(defaults.ACCEPT_LANGUAGES) or "en",
        profile=user.profile,
    )

    for k, v in user_session.dict().items():
        session[k] = v


def websocket_acl(acl_type):
    def check_acl(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                await verify_session(acl_type)

                if not session["login"] in app.config["WS_CONNECTIONS"]:
                    app.config["WS_CONNECTIONS"][session["login"]] = dict()

                app.config["WS_CONNECTIONS"][session["login"]].update(
                    {websocket._get_current_object(): "opened"}
                )

                return await fn(*args, **kwargs)
            except AuthException as e:
                abort(401)
            finally:
                if "login" in session:
                    for ws in app.config["WS_CONNECTIONS"].get(session["login"], {}):
                        if ws == websocket._get_current_object():
                            del app.config["WS_CONNECTIONS"][session["login"]][ws]
                            break

        return wrapper

    return check_acl


def acl(acl_type):
    def check_acl(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                if "x-access-token" in request.headers:
                    await create_session_by_token(request.headers["x-access-token"])

                await verify_session(acl_type)

                return await fn(*args, **kwargs)

            except AuthException as e:
                client_addr = request.headers.get(
                    "X-Forwarded-For", request.remote_addr
                )
                logger.warning(
                    f'{client_addr} - {session.get("login")}[ID={session.get("id")}] tried to access {request.path}'
                )

                if "hx-request" in request.headers:
                    return trigger_notification(
                        level="error",
                        response_body="",
                        response_code=401,
                        title="Authentication Required",
                        message=str(e),
                    )
                else:
                    if "x-access-token" in request.headers:
                        return (f"Authentication Required\n{str(e)}\n", 401)
                    return redirect(url_for("main.root"))

        return wrapper

    return check_acl


def formoptions(options):
    def inject_options(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            request.form_options = dict()
            for option in options:
                if option == "users":
                    request.form_options[option] = [
                        {"name": user.login, "value": user.id, "groups": user.groups}
                        for user in await search_users(name="")
                    ]
                else:
                    request.form_options[option] = [
                        {"name": o.name, "value": o.id}
                        for o in await search_object(
                            object_type=option,
                            match_all={"assigned_users": [session["id"]]}
                            if not "system" in session["acl"]
                            else {},
                        )
                    ]

            for o in request.form_options:
                request.form_options[o] = sorted(
                    request.form_options[o], key=lambda x: x["name"]
                )

            return await fn(*args, **kwargs)

        return wrapper

    return inject_options
