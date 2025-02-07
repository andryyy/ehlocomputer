import asyncio
import fileinput
import json

from config import defaults
from config.cluster import ClusterLock, cluster
from config.database import *
from datetime import datetime
from models import system as system_model
from models.tables import TableSearchHelper
from pydantic import ValidationError
from quart import Blueprint, current_app as app, render_template, request, session
from tools.system import get_system_settings, list_application_log_files
from utils import wrappers
from utils.helpers import batch, expire_key
from utils.datetimes import ntime_utc_now
from web.helpers import trigger_notification, validation_error, ws_htmx

blueprint = Blueprint("system", __name__, url_prefix="/system")


@blueprint.context_processor
def load_context():
    context = dict()

    context["schemas"] = {
        "system_settings": system_model.SystemSettings.model_json_schema()
    }

    if cluster.master_node != defaults.CLUSTER_PEERS_ME:
        try:
            current_master = cluster.connections[cluster.master_node]["meta"]["name"]
        except:
            current_master = "Starting..."
    else:
        current_master = defaults.NODENAME
    context["current_master"] = current_master

    return context


@blueprint.route("/cluster/enforce-transaction/<action>", methods=["POST"])
@wrappers.acl("system")
async def cluster_enforce_commit(action: str):
    if action == "start":
        if not IN_MEMORY_DB.get("enforce_commit", False):
            IN_MEMORY_DB["enforce_commit"] = ntime_utc_now()
            IN_MEMORY_DB["connection_failures"] = dict()
            app.add_background_task(
                expire_key,
                IN_MEMORY_DB,
                "enforce_commit",
                defaults.CLUSTER_ENFORCE_COMMIT_TIMEOUT,
            )
            await ws_htmx(
                "system",
                "beforeend",
                """<div hidden _="on load trigger
                    notification(
                    title: 'Enforced transaction mode',
                    level: 'system',
                    message: 'Caution: Enforced transaction mode is now enabled',
                    duration: 10000
                    )"></div>""",
            )

            return trigger_notification(
                level="success",
                response_code=204,
                title="Activated",
                message="Enforced transaction mode is enabled",
            )
        else:
            return trigger_notification(
                level="warning",
                response_code=409,
                title="Already active",
                message="Enforced transaction mode is already enabled",
            )
    elif action == "stop":
        IN_MEMORY_DB["enforce_commit"] = False
        await ws_htmx(
            "system",
            "beforeend",
            '<div hidden _="on load remove #enforce-commit-button trigger '
            + "notification(title: 'Enforced transaction disabled', level: 'system', message: 'Enforced transaction mode is now disabled', duration: 10000)\"></div>",
        )
        return trigger_notification(
            level="success",
            response_code=204,
            title="Deactivated",
            message="Enforced transaction mode is disabled",
        )


@blueprint.route("/cluster/reset-failed-peer", methods=["POST"])
@wrappers.acl("system")
async def cluster_reset_failed_peer():
    peer = request.form_parsed.get("peer")
    if peer and peer in IN_MEMORY_DB["connection_failures"]:
        IN_MEMORY_DB["connection_failures"][peer] = 0
        return trigger_notification(
            level="success",
            response_code=204,
            title="Peer reset",
            message="Peer failed counter was reset",
        )
    else:
        return trigger_notification(
            level="error",
            response_code=409,
            title="Unknown peer",
            message="Peer was not reset",
        )


@blueprint.route("/status", methods=["GET"])
@wrappers.acl("system")
async def status():
    status = {
        "peer_critical": IN_MEMORY_DB["peer_critical"],
        "connection_failures": IN_MEMORY_DB["connection_failures"],
        "enforce_commit": IN_MEMORY_DB.get("enforce_commit", False),
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
        (
            search_model,
            page,
            page_size,
            sort_attr,
            sort_reverse,
            filters,
        ) = TableSearchHelper(
            request.form_parsed,
            "system_logs",
            default_sort_attr="record.time.repr",
            default_sort_reverse=True,
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


@blueprint.route("/logs/refresh")
@wrappers.acl("system")
async def refresh_cluster_logs():
    await ws_htmx(
        session["login"],
        "beforeend",
        "<div hidden _=\"on load trigger notification(title: 'Please wait', level: 'user', message: 'Refreshing cluster logs...', duration: 2000)\"></div>",
        "/system/logs",
    )

    if not IN_MEMORY_DB.get("application_logs_refresh") or request.args.get("force"):
        IN_MEMORY_DB["application_logs_refresh"] = ntime_utc_now()
        app.add_background_task(
            expire_key,
            IN_MEMORY_DB,
            "application_logs_refresh",
            defaults.CLUSTER_LOGS_REFRESH_AFTER,
        )
        async with ClusterLock("files") as c:
            await c.request_files("logs/application.log", defaults.CLUSTER_PEERS_THEM)

    refresh_ago = round(ntime_utc_now() - IN_MEMORY_DB["application_logs_refresh"])

    await ws_htmx(
        session["login"],
        "beforeend",
        "<div hidden _=\"on load trigger notification(title: 'Task completed', level: 'success', message: 'Application logs were collected', duration: 2000) then "
        + "trigger logsReady on #system-logs-table-search "
        + f'then put {refresh_ago} into #system-logs-last-refresh"></div>',
        "/system/logs",
    )
    return "", 204
