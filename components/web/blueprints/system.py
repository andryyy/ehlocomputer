import asyncio
import components.system
import fileinput
import json
import os

from components.cluster.cluster import cluster
from components.models.system import SystemSettings, UpdateSystemSettings
from components.utils import batch, expire_key
from components.utils.datetimes import datetime, ntime_utc_now
from components.web.utils import *

blueprint = Blueprint("system", __name__, url_prefix="/system")
log_lock = asyncio.Lock()

IN_MEMORY_DB["application_logs_full_pull"] = dict()


@blueprint.context_processor
def load_context():
    context = dict()
    context["schemas"] = {"system_settings": SystemSettings.model_json_schema()}

    if cluster.master_node != defaults.CLUSTER_PEERS_ME:
        try:
            current_master = cluster.connections[cluster.master_node]["meta"]["name"]
        except:
            current_master = "Starting..."
    else:
        current_master = defaults.CLUSTER_NODENAME
    context["current_master"] = current_master

    return context


@blueprint.route("/cluster/enforce-transaction/<action>", methods=["POST"])
@acl("system")
async def cluster_enforce_commit(action: str):
    if action == "start":
        if not IN_MEMORY_DB.get("enforce_commit", False):
            IN_MEMORY_DB["enforce_commit"] = ntime_utc_now()
            IN_MEMORY_DB["PEER_CONNECTION_FAILURES"] = dict()
            current_app.add_background_task(
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
@acl("system")
async def cluster_reset_failed_peer():
    peer = request.form_parsed.get("peer")
    if peer and peer in IN_MEMORY_DB["PEER_CONNECTION_FAILURES"]:
        IN_MEMORY_DB["PEER_CONNECTION_FAILURES"][peer] = 0
        IN_MEMORY_DB["PEER_CRIT"].pop(cluster.master_node, None)
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
@acl("system")
async def status():
    status = {
        "PEER_CRIT": IN_MEMORY_DB["PEER_CRIT"],
        "connection_failures": IN_MEMORY_DB["PEER_CONNECTION_FAILURES"],
        "enforce_commit": IN_MEMORY_DB.get("enforce_commit", False),
        "web_requests": IN_MEMORY_DB["WEB_REQUESTS"],
        "connections": cluster.connections,
    }
    return await render_template("system/status.html", data={"status": status})


@blueprint.route("/settings", methods=["PATCH"])
@acl("system")
async def write_settings():
    try:
        UpdateSystemSettingsModel = UpdateSystemSettings.parse_obj(request.form_parsed)
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
@acl("system")
async def settings():
    try:
        settings = await components.system.get_system_settings()
    except ValidationError as e:
        return validation_error(e.errors())

    return await render_template("system/settings.html", settings=settings)


@blueprint.route("/logs")
@blueprint.route("/logs/search", methods=["POST"])
@acl("system")
async def cluster_logs():
    try:
        (
            search_model,
            page,
            page_size,
            sort_attr,
            sort_reverse,
            filters,
        ) = table_search_helper(
            request.form_parsed,
            "system_logs",
            default_sort_attr="record.time.repr",
            default_sort_reverse=True,
        )
    except ValidationError as e:
        return validation_error(e.errors())

    if request.method == "POST":
        _logs = []
        async with log_lock:
            parser_failed = False

            with fileinput.input(
                components.system.list_application_log_files(), encoding="utf-8"
            ) as f:
                for line in f:
                    if search_model.q in line:
                        try:
                            _logs.append(json.loads(line.strip()))
                        except json.decoder.JSONDecodeError:
                            parser_failed = True
                            os.unlink(f.filename())
                            f.nextfile()

            if parser_failed:
                return trigger_notification(
                    level="warning",
                    response_code=409,
                    title="Trying again",
                    message="Update failed, retrying...",
                    additional_triggers={"forceRefresh": ""},
                )

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
@acl("system")
async def refresh_cluster_logs():
    await ws_htmx(
        session["login"],
        "beforeend",
        '<div class="loading-logs" hidden _="on load trigger '
        + "notification("
        + "title: 'Please wait', level: 'user', "
        + "message: 'Requesting logs, your view will be updated automatically.', duration: 10000)\">"
        + "</div>",
        "/system/logs",
    )

    if not IN_MEMORY_DB.get("application_logs_refresh") or request.args.get("force"):
        IN_MEMORY_DB["application_logs_refresh"] = ntime_utc_now()

        current_app.add_background_task(
            expire_key,
            IN_MEMORY_DB,
            "application_logs_refresh",
            defaults.CLUSTER_LOGS_REFRESH_AFTER,
        )

        async with log_lock:
            async with ClusterLock("files", current_app):
                for peer in cluster.connections.keys():
                    if not peer in IN_MEMORY_DB["application_logs_full_pull"]:
                        IN_MEMORY_DB["application_logs_full_pull"][peer] = True
                        current_app.add_background_task(
                            expire_key,
                            IN_MEMORY_DB["application_logs_full_pull"],
                            peer,
                            36000,
                        )
                        start = 0
                    else:
                        start = -1
                        file_path = f"peer_files/{peer}/logs/application.log"
                        if os.path.exists(file_path) and os.path.getsize(file_path) > (
                            5 * 1024 * 1024
                        ):
                            start = 0

                    await cluster.request_files(
                        "logs/application.log", [peer], start, -1
                    )

            missing_peers = ", ".join(
                [
                    p
                    for p in defaults.CLUSTER_PEERS_THEM
                    if p not in cluster.connections.keys()
                ]
            )

            if missing_peers:
                await ws_htmx(
                    session["login"],
                    "beforeend",
                    '<div hidden _="on load trigger '
                    + "notification("
                    + "title: 'Missing peers', level: 'warning', "
                    + f"message: 'Some peers seem to be offline and were not pulled: {missing_peers}', duration: 3000)\">"
                    + "</div>",
                    "/system/logs",
                )

    refresh_ago = round(ntime_utc_now() - IN_MEMORY_DB["application_logs_refresh"])

    await ws_htmx(
        session["login"],
        "beforeend",
        '<div hidden _="on load trigger logsReady on #system-logs-table-search '
        + f"then put {refresh_ago} into #system-logs-last-refresh "
        + f'then wait 500 ms then trigger removeNotification on .notification-user"></div>',
        "/system/logs",
    )

    return "", 204
