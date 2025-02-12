import asyncio
import json
import os
from config import defaults
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


@blueprint.route("/logout", methods=["POST", "GET"])
async def logout():
    session_clear()
    return ("", 200, {"HX-Redirect": "/"})


@blueprint.websocket("/ws")
@wrappers.websocket_acl("any")
async def ws():
    while True:
        await websocket.send(
            f'<div class="no-text-decoration" data-tooltip="Connected" id="ws-indicator" hx-swap-oob="outerHTML">🟢</div>'
        )
        data = await websocket.receive()
        try:
            data_dict = json.loads(data)
            if "path" in data_dict:
                app.config["WS_CONNECTIONS"][session["login"]][
                    websocket._get_current_object()
                ] = data_dict["path"]

        except:
            pass
