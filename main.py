import aiohttp
import asyncio
import json
import os
import re
import requests
import sys
import traceback

from config import defaults, logger
from config.database import r, TinyDB, Query
from quart import Quart, redirect, render_template, request, session, url_for
from threading import Thread
from utils import consumer
from utils import helpers
from utils.hypercorn.middleware import ReadTrustedProxyHeaders
from uuid import uuid4
from views import auth as auth_view
from views import configs as config_view
from views import listeners as listeners_view
from views import objects as objects_view
from views import profile as profile_view
from views import realms as realms_view


app = Quart(
    __name__,
    static_url_path="/static",
    static_folder="static_files",
    template_folder="templates",
)
app.secret_key = os.getenv("SESSION_SECRET", "im-insecure")
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 31536000


@app.before_serving
async def app_startup():
    thread = Thread(
        target=consumer.consumer, daemon=True, name=f"pid-{os.getpid()}-consumer"
    )
    thread.start()
    r.xadd("ehlotalk", {"command": "setup_realm"})
    r.xadd("ehlotalk", {"command": "run_podman"})


@app.before_request
def add_realm_data():
    hostname = request.headers.get("Host")
    request.realm_data = helpers.get_realm_by_hostname(hostname)


# Temporarily disable caching
@app.after_request
def add_header(response):
    # return response  # indicates caching
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Cache-Control"] = "public, max-age=0"
    return response  # indicates no caching


@app.context_processor
def load_defaults():
    return {
        k: v
        for k, v in defaults.__dict__.items()
        if not (k.startswith("__") or k.startswith("_"))
    }


@app.template_filter(name="hex")
def to_hex(value):
    return value.hex()


@app.route("/")
async def root():
    with TinyDB(path="realms/realms.json") as db:
        if db.table("realms").search(Query().bootstrapped == True):
            if session.get("id"):
                return redirect(url_for("profile.user_profile_get"))
            session.clear()
            return await render_template("auth/authenticate.html")
        else:
            session.clear()
            return await render_template(
                "auth/bootstrap.html",
                data={
                    "token_lifetime": r.ttl("setup_realm:bootstraptoken"),
                    "realm_id": db.table("realms").get(Query().default == True)["id"],
                },
            )


@app.route("/nchan/auth/<user>")
@helpers.user_session_required
async def nchan_auth(user: str):
    if session.get("login") == user:
        return "", 200
    return "", 403


@app.route("/logout", methods=["POST"])
@helpers.user_session_required
async def logout_post():
    session.clear()
    return (
        "",
        200,
        {
            "HX-Redirect": "/",
        },
    )


app.register_blueprint(auth_view.auth)
app.register_blueprint(profile_view.profile)
app.register_blueprint(objects_view.objects)
app.register_blueprint(config_view.configs)
app.register_blueprint(realms_view.realms)
app.register_blueprint(listeners_view.listeners)

ehlo = ReadTrustedProxyHeaders(app)
