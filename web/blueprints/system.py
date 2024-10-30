import asyncio
import fileinput
import json

from config import *
from config.cluster import cluster
from datetime import datetime
from models.tables import TableSearchHelper
from models import system as system_model
from pydantic import ValidationError
from quart import Blueprint, current_app as app, render_template, request, session
from tools.cluster import get_peer_files
from tools.system import get_system_settings, list_application_log_files
from utils import wrappers
from utils.helpers import batch
from web.helpers import trigger_notification, validation_error, ws_htmx

blueprint = Blueprint("system", __name__, url_prefix="/system")


@blueprint.context_processor
def load_system_defaults():
    schemas = {
        f"_{schema_type}_schema": v.model_json_schema()
        for schema_type, v in system_model.model_classes["forms"].items()
    }
    return {
        "schemas": schemas,
    }


@blueprint.route("/settings", methods=["PATCH"])
@wrappers.acl("system")
async def write_settings():
    try:
        UpdateSystemSettingsModel = system_model.UpdateSystemSettings.parse_obj(
            request.form_parsed
        )
    except ValidationError as e:
        return validation_error(e.errors())

    async with TinyDB(**TINYDB_PARAMS) as db:
        db.table("system_settings").remove(doc_ids=[1])
        db.table("system_settings").insert(
            Document(UpdateSystemSettingsModel.dict(), doc_id=1)
        )

    return trigger_notification(
        level="success",
        response_body="",
        response_code=204,
        title="Settings updated",
        message="System settings were updated",
    )


@blueprint.route("/settings")
@wrappers.acl("system")
async def settings():
    try:
        settings = await get_system_settings()
    except ValidationError as e:
        return validation_error(e.errors())

    return await render_template("system/settings.html", settings=settings)


@blueprint.route("/logs")
@blueprint.route("/logs/search", methods=["POST"])
@wrappers.acl("system")
async def cluster_logs():
    try:
        search_model, page, page_size, sort_attr, sort_reverse = TableSearchHelper(
            request.form_parsed, "system_logs", default_sort_attr="record.time.repr"
        )
    except ValidationError as e:
        return validation_error(e.errors())

    if request.method == "POST":
        _logs = []
        for line in fileinput.input(list_application_log_files()):
            if search_model.q in line:
                _logs.append(json.loads(line.strip()))

        def system_logs_sort_func(sort_attr):
            if sort_attr == "text":
                return lambda d: (
                    d["text"],
                    datetime.fromisoformat(d["record"]["time"]["repr"]).timestamp(),
                )
            elif sort_attr == "record.level.no":
                return lambda d: (
                    d["record"]["level"]["no"],
                    datetime.fromisoformat(d["record"]["time"]["repr"]).timestamp(),
                )
            else:  # fallback to "record.time.repr"
                return lambda d: datetime.fromisoformat(
                    d["record"]["time"]["repr"]
                ).timestamp()

        log_pages = [
            m
            for m in batch(
                sorted(
                    _logs,
                    key=system_logs_sort_func(sort_attr),
                    reverse=sort_reverse,
                ),
                page_size,
            )
        ]

        try:
            log_pages[page - 1]
        except IndexError:
            page = len(log_pages)

        system_logs = log_pages[page - 1] if page else log_pages

        return await render_template(
            "system/includes/logs/table_body.html",
            data={
                "logs": system_logs,
                "page_size": page_size,
                "page": page,
                "pages": len(log_pages),
                "elements": len(_logs),
            },
        )
    else:
        return await render_template("system/logs.html")


@blueprint.route("/logs/refresh-cluster-logs")
@wrappers.acl("system")
async def refresh_cluster_logs():
    await ws_htmx(
        session["login"],
        "beforeend",
        "<div hidden _=\"on load trigger notification(title: 'Please wait', level: 'user', message: 'Refreshing cluster logs...', duration: 2000)\"></div>",
        "/system/logs",
    )

    await cluster.acquire_lock()
    await get_peer_files(cluster, defaults.CLUSTER_PEERS_THEM, "logs/application.log")
    await cluster.release()

    await ws_htmx(
        session["login"],
        "beforeend",
        "<div hidden _=\"on load trigger notification(title: 'Task completed', level: 'success', message: 'Application logs were collected', duration: 2000) then "
        + 'trigger clusterLogsReady on #system-logs-table-search"></div>',
        "/system/logs",
    )
    return "", 204
