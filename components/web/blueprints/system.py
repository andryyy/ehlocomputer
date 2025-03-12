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


@blueprint.context_processor
def load_context():
    context = dict()
    context["schemas"] = {"system_settings": SystemSettings.model_json_schema()}

    if cluster.master_node != cluster.peers.local_name:
        try:
            current_master = cluster.connections[cluster.master_node]["meta"]["name"]
        except:
            current_master = "Starting..."
    else:
        current_master = defaults.CLUSTER_NODENAME
    context["current_master"] = current_master

    return context


@blueprint.route("/cluster/update-status", methods=["POST"])
@acl("system")
async def cluster_status_update():
    async with ClusterLock("status", current_app):
        async with cluster.receiving:
            ticket, receivers = await cluster.send_command("STATUS", "*")
            await cluster.await_receivers(ticket, receivers, raise_err=False)

    return redirect(url_for("system.status"))


@blueprint.route("/cluster/db/enforce-updates", methods=["POST"])
@acl("system")
async def cluster_db_enforce_updates():
    toggle = request.form_parsed.get("toggle", "off")
    if toggle == "on":
        if not IN_MEMORY_DB.get("ENFORCE_DBUPDATE", False):
            IN_MEMORY_DB["ENFORCE_DBUPDATE"] = ntime_utc_now()
            current_app.add_background_task(
                expire_key,
                IN_MEMORY_DB,
                "ENFORCE_DBUPDATE",
                defaults.CLUSTER_ENFORCE_DBUPDATE_TIMEOUT,
            )
            await ws_htmx(
                "system",
                "beforeend",
                """<div hidden _="on load trigger
                    notification(
                    title: 'Cluster notification',
                    level: 'system',
                    message: 'Enforced database updates are enabled',
                    duration: 5000
                    )"></div>""",
            )

            return trigger_notification(
                level="success",
                response_code=204,
                title="Activated",
                message="Enforced database updates are enabled",
            )
        else:
            return trigger_notification(
                level="warning",
                response_code=409,
                title="Already active",
                message="Enforced database updates are already enabled",
            )
    elif toggle == "off":
        IN_MEMORY_DB["ENFORCE_DBUPDATE"] = False
        await ws_htmx(
            "system",
            "beforeend",
            '<div hidden _="on load remove #enforce-dbupdate-button then trigger '
            + "notification(title: 'Cluster notification', level: 'system', message: 'Enforced database updates are now disabled', duration: 5000)\"></div>",
        )
        return trigger_notification(
            level="success",
            response_code=204,
            title="Deactivated",
            message="Enforced transaction mode is disabled",
        )


@blueprint.route("/status", methods=["GET"])
@acl("system")
async def status():
    status = {
        "PEER_CRIT": IN_MEMORY_DB["PEER_CRIT"],
        "ENFORCE_DBUPDATE": IN_MEMORY_DB.get("ENFORCE_DBUPDATE", False),
        "CLUSTER_CONNECTIONS": cluster.connections,
        "CLUSTER___META": cluster._meta,
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
                    if not peer in IN_MEMORY_DB["APP_LOGS_FULL_PULL"]:
                        IN_MEMORY_DB["APP_LOGS_FULL_PULL"][peer] = True
                        current_app.add_background_task(
                            expire_key,
                            IN_MEMORY_DB["APP_LOGS_FULL_PULL"],
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

                    await cluster.request_files("logs/application.log", peer, start, -1)

            missing_peers = ", ".join(
                [
                    p["name"]
                    for p in defaults.CLUSTER_PEERS
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
