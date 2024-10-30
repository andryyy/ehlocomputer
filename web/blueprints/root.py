import asyncio
import json
import os
from config import *
from quart import (
    Blueprint,
    redirect,
    render_template,
    session,
    url_for,
    current_app as app,
    request,
    websocket,
)
from utils import wrappers
from utils.crypto import *
from web.helpers import session_clear
from utils.helpers import is_path_within_cwd
from utils.datetimes import last_modified_http, parse_last_modified_http, ntime_utc_now

blueprint = Blueprint("main", __name__, url_prefix="/")


@blueprint.route("/")
async def root():
    if session.get("id"):
        return redirect(url_for("profile.user_profile_get"))

    session_clear()
    return await render_template("auth/authenticate.html")


@blueprint.route("/file_write", methods=["POST"])
async def file_write():
    file = request.form_parsed.get("file")
    payload = request.form_parsed.get("data")

    assert is_path_within_cwd(file) == True, "Illegal path"

    data = fernet_decrypt(payload, defaults.SECRET_KEY)
    os.makedirs(os.path.dirname(file), exist_ok=True)

    with open(file, "w") as f:
        f.write(data)

    return "", 200


@blueprint.route("/file_read", methods=["POST"])
async def file_read():
    file = request.form_parsed.get("file")

    assert is_path_within_cwd(file) == True, "Illegal path"

    if_modified_since = request.headers.get("If-Modified-Since")
    if_modified_since_time = parse_last_modified_http(if_modified_since)

    file_last_modified = last_modified_http(file)
    file_last_modified_time = parse_last_modified_http(file_last_modified)

    if file_last_modified_time <= if_modified_since_time:
        return "", 304

    with open(file, "r") as f:
        return (
            fernet_encrypt(f.read(), defaults.SECRET_KEY),
            200,
            {"Last-Modified": file_last_modified},
        )


@blueprint.route("/logout", methods=["POST", "GET"])
async def logout():
    session_clear()
    return ("", 200, {"HX-Redirect": "/"})


@blueprint.websocket("/ws")
@wrappers.websocket_acl("any")
async def ws():
    while True:
        data = await websocket.receive()
        try:
            data_dict = json.loads(data)
            if "path" in data_dict:
                app.config["WS_CONNECTIONS"][session["login"]][
                    websocket._get_current_object()
                ] = data_dict["path"]
        except:
            pass
