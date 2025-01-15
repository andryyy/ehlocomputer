import asyncio
import json
import os
import time

from config import defaults
from config.cluster import ClusterHTTPException
from contextlib import suppress
from quart import Quart, request
from utils.cluster import Cluster
from utils.helpers import merge_deep
from web.blueprints import auth
from web.blueprints import objects
from web.blueprints import profile
from web.blueprints import root
from web.blueprints import system
from web.blueprints import users
from web.helpers import parse_form_to_dict, trigger_notification
from werkzeug.exceptions import HTTPException

app = Quart(
    __name__,
    static_url_path="/static",
    static_folder="../static_files",
    template_folder="../templates",
)

app.register_blueprint(root.blueprint)
app.register_blueprint(auth.blueprint)
app.register_blueprint(objects.blueprint)
app.register_blueprint(profile.blueprint)
app.register_blueprint(system.blueprint)
app.register_blueprint(users.blueprint)

app.config["SEND_FILE_MAX_AGE_DEFAULT"] = defaults.SEND_FILE_MAX_AGE_DEFAULT
app.config["SECRET_KEY"] = defaults.SECRET_KEY
app.config["TEMPLATES_AUTO_RELOAD"] = defaults.TEMPLATES_AUTO_RELOAD
app.config["SERVER_NAME"] = defaults.HOSTNAME
app.config["SESSION_VALIDATED"] = dict()
app.config["WS_CONNECTIONS"] = dict()


@app.errorhandler(ClusterHTTPException)
async def handle_cluster_error(error):
    return trigger_notification(
        level="error",
        response_body="",
        response_code=204,
        title="Cluster error",
        message=f"🤖 Computer failed, oh no... ({error})",
    )


@app.before_request
async def before_request():
    request.form_parsed = {}
    request.locked = False
    if request.method in ["POST", "PATCH", "PUT", "DELETE"]:
        form = await request.form
        request.form_parsed = dict()
        if form:
            for k in form:
                v = form.getlist(k)
                if len(v) == 1:
                    request.form_parsed = merge_deep(
                        request.form_parsed, parse_form_to_dict(k, v.pop())
                    )
                else:
                    request.form_parsed = merge_deep(
                        request.form_parsed, parse_form_to_dict(k, v)
                    )


@app.after_request
async def after_request(response):
    if defaults.DISABLE_CACHE == False:
        return response

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Cache-Control"] = "public, max-age=0"

    return response


@app.teardown_request
async def teardown_request(exc):
    if isinstance(exc, asyncio.exceptions.CancelledError):
        with suppress(Exception):
            await cluster.release()


@app.context_processor
def load_defaults():
    _defaults = {
        k: v
        for k, v in defaults.__dict__.items()
        if not (k.startswith("__") or k.startswith("_"))
    }
    return _defaults


@app.template_filter(name="hex")
def to_hex(value):
    return value.hex()


@app.template_filter(name="toprettyjson")
def to_prettyjson(value):
    return json.dumps(value, sort_keys=True, indent=2, separators=(",", ": "))
