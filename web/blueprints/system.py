import asyncio
import fileinput
import json

from config import defaults
from config.cluster import ClusterLock, cluster
from config.database import IN_MEMORY_DB
from datetime import datetime
from models import system as system_model
from models.tables import TableSearchHelper
from pydantic import ValidationError
from quart import Blueprint, current_app as app, render_template, request, session
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
    if cluster.master_node != defaults.CLUSTER_PEERS_ME:
        try:
            current_master = cluster.connections[cluster.master_node]["meta"]["name"]
        except:
            current_master = "Starting..."
    else:
        current_master = defaults.NODENAME

    return {"schemas": schemas, "current_master": current_master}


@blueprint.route("/cluster/reset-failed-peer", methods=["POST"])
@wrappers.acl("system")
async def cluster_reset_failed_peer():
    peer = request.form_parsed.get("peer")
    if peer and peer in IN_MEMORY_DB["peer_failures"]:
        IN_MEMORY_DB["peer_failures"][peer] = 0
        return trigger_notification(
            level="success",
            response_body="",
            response_code=204,
            title="Peer reset",
            message="Peer failed counter was reset",
        )
    else:
        return trigger_notification(
            level="error",
            response_body="",
            response_code=409,
            title="Unknown peer",
            message="Peer was not reset",
        )


@blueprint.route("/status", methods=["GET"])
@wrappers.acl("system")
async def status():
    status = {
        "peer_failures": IN_MEMORY_DB["peer_failures"],
        "connections": cluster.connections,
    }
    return await render_template("system/status.html", data={"status": status})


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

    async with ClusterLock("main") as c:
        await c.request_files("logs/application.log", defaults.CLUSTER_PEERS_THEM)

    await ws_htmx(
        session["login"],
        "beforeend",
        "<div hidden _=\"on load trigger notification(title: 'Task completed', level: 'success', message: 'Application logs were collected', duration: 2000) then "
        + 'trigger clusterLogsReady on #system-logs-table-search"></div>',
        "/system/logs",
    )
    return "", 204
