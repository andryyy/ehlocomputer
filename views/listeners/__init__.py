import aiohttp
import asyncio
import json

from . import tools as listeners_helpers
from .pods import Listener
from config import defaults, lego, logger
from config.database import *
from models import listeners as listeners_model
from pathlib import Path
from podman import PodmanClient
from pydantic import ValidationError
from quart import Blueprint, render_template, request, session
from typing import Literal
from utils import helpers
from uuid import uuid4

listeners = Blueprint("listeners", __name__, url_prefix="/listeners")


@listeners.route("/", methods=["GET"])
@helpers.user_session_required
async def root():
    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        listener_table = db.table("listeners")
        data = listener_table.all()

    template = render_template("listeners/listeners.html", data=data)
    return await template


@listeners.route("/<listener_id>", defaults={"revision": None}, methods=["GET"])
@listeners.route("/<listener_id>/revision/<revision>", methods=["GET"])
@helpers.user_session_required
async def get_listener(listener_id: str, revision: str | None):
    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        listener = db.table("listeners").get(Query().id == listener_id)
        listener["available_configs"] = [
            (x["id"], x["name"]) for x in db.table("configs").all()
        ]

    tpl = "listeners/listener.html"
    if revision:
        listener["configuration"] = next(
            (
                historic
                for historic in listener.get("historic", [])
                if historic.get("revision") == revision
            ),
            {},
        )
        tpl = "listeners/includes/listener_config.html"

    template = render_template(tpl, listener=listener)
    return await template


@listeners.route("/<listener_id>", methods=["DELETE"])
async def delete_listener(listener_id: str):
    try:
        listener_by_id = listeners_helpers.get_listener_by_id(
            listener_id=listener_id, realm_path=request.realm_data.get("path")
        )
        if not listener_by_id:
            return helpers.validation_error(
                [{"loc": ["id"], "msg": f"Listener ID {listener_id} does not exist"}]
            )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        db.table("listeners").remove(Query().id == listener_id)

    return (
        "",
        200,
        {"HX-Location": json.dumps({"path": "/listeners", "target": "#body-main"})},
    )


@listeners.route("/<listener_id>/certificate", methods=["GET"])
@helpers.user_session_required
async def get_certificate_status(listener_id: str, nocache=False):
    try:
        l = Listener(listener_id=listener_id, realm_data=request.realm_data)
        cert_status = l.validate_certificate(nocache="nocache" in request.args)
    except Exception as e:
        return helpers.validation_error([{"loc": [], "msg": str(e)}])

    return await render_template(
        "listeners/partials/tls/cert_status.html", cert_status=cert_status
    )


@listeners.route("/<listener_id>/status", methods=["GET"])
@helpers.user_session_required
async def get_listener_status(listener_id: str):
    listener_containers = {}
    try:
        with PodmanClient(
            base_url=f"unix://{request.realm_data['podman_socket']}"
        ) as client:
            for container in client.containers.list(
                all=True,
                filters=[
                    f"label=listener_id={listener_id}",
                ],
            ):
                if container.labels.get("worker"):
                    listener_containers.update(
                        {container.labels.get("worker"): container.attrs}
                    )
    except Exception as e:
        listener_containers = False

    return await render_template(
        "listeners/partials/listener_status.html",
        listener_containers=listener_containers,
    )


@listeners.route("/", methods=["POST"])
@helpers.user_session_required
async def create_listener():
    req_body_dict = await request.json
    try:
        ListenerCreateModel = listeners_model.ListenerCreate.parse_obj(req_body_dict)
        if listeners_helpers.get_listener_by_name(
            name=ListenerCreateModel.name, realm_path=request.realm_data.get("path")
        ):
            return helpers.validation_error(
                [{"loc": ["name"], "msg": f"Listener name exists"}]
            )
    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        listener_table = db.table("listeners")
        listener_table.insert(ListenerCreateModel.dict())

    template = render_template(
        "listeners/partials/listener_row.html",
        data={"listener_id": ListenerCreateModel.id, "name": ListenerCreateModel.name},
    )
    return await template


"""
START of TLS processing routes
"""


@listeners.route("/<listener_id>/tls", methods=["GET"])
@helpers.user_session_required
async def acme_tls_provider(listener_id: str):
    template = render_template(
        "listeners/partials/tls/provider.html",
        lego_dns_providers=lego.LEGO_DNS_PROVIDERS,
    )
    return await template


@listeners.route("/<listener_id>/tls/<cli_name>", methods=["GET"])
@helpers.user_session_required
async def acme_tls_provider_config(listener_id: str, cli_name: str):
    try:
        listener_by_id = listeners_helpers.get_listener_by_id(
            listener_id, realm_path=request.realm_data.get("path")
        )
        hostname = listener_by_id["configuration"].get("hostname")
        if not listener_by_id or not hostname:
            return helpers.validation_error(
                [
                    {
                        "loc": ["id"],
                        "msg": f"Listener ID {listener_id} does not exist or provides no hostname",
                    }
                ]
            )
    except ValidationError as e:
        return helpers.validation_error(e.errors())

    template = render_template(
        "listeners/partials/tls/config.html",
        data={
            "hostname": hostname,
            "client_name": cli_name,
            "client_data": lego.LEGO_DNS_PROVIDERS.get(cli_name, []),
        },
    )
    return await template


@listeners.route("/<listener_id>/tls/<cli_name>/<command>", methods=["POST"])
@helpers.user_session_required
async def acme_lego_setup(
    listener_id: str, cli_name: str, command: Literal["run", "renew"]
):
    req_body_dict = await request.json

    if command == "run":
        try:
            ListenerLegoConfigModel = listeners_model.ListenerLegoConfig.parse_obj(
                req_body_dict
            )
        except ValidationError as e:
            return helpers.validation_error(e.errors())

        lego_config = ListenerLegoConfigModel.dict(
            exclude={"acme_terms_agreed", "provider_config"}
        )
        lego_config.update(ListenerLegoConfigModel.provider_config)

        container_handler = Listener(
            listener_id=listener_id, realm_data=request.realm_data
        )
        container_handler.acquire_certificate(lego_config, "run")

        session["lego_config"] = lego_config

        return await render_template("listeners/partials/tls/terminal.html")

    elif command == "renew":
        if not session.get("lego_config"):
            return helpers.show_alert(
                "genericError",
                "",
                204,
                "Listener not modified",
                "Lost track of session, pleaese try again",
            )

        lego_config = session["lego_config"]

        container_handler = Listener(
            listener_id=listener_id, realm_data=request.realm_data
        )
        container_handler.acquire_certificate(lego_config, "renew")

        session["lego_config"] = None
        return (
            "",
            200,
            {
                "HX-Location": json.dumps(
                    {"path": f"/listeners/{listener_id}", "target": "#body-main"}
                )
            },
        )


"""
END of TLS processing routes
"""


@listeners.route("/<listener_id>/terminal/<worker>", methods=["GET"])
@helpers.user_session_required
async def container_terminal(listener_id: str, worker: str):
    stream_id = str(uuid4())
    stream = listeners_helpers.Stream(
        listener_id, worker, stream_id, request.realm_data["podman_socket"]
    )
    loop = asyncio.get_event_loop()
    loop.create_task(stream.run())
    template = render_template("listeners/partials/terminal.html", stream_id=stream_id)
    return await template


@listeners.route("/<listener_id>/control/<worker>/<command>", methods=["GET"])
@helpers.user_session_required
async def container_control(
    listener_id: str, worker: str, command: Literal["restart", "reload_config"]
):
    if worker == "smtpd":
        container_handler = Listener(
            listener_id=listener_id, realm_data=request.realm_data
        )
        match command:
            case "restart":
                container_handler.smtpd(command="restart")
            case "reload_config":
                container_handler.smtpd(command="reload_config")
    else:
        match command:
            case "restart":
                container_name = listeners_helpers.get_container_name(
                    listener_id, worker, request.realm_data["podman_socket"]
                )
                with PodmanClient(
                    base_url=f"unix://{request.realm_data['podman_socket']}"
                ) as client:
                    client.containers.get(container_name).restart()

    match command:
        case "delete":
            container_name = listeners_helpers.get_container_name(
                listener_id, worker, request.realm_data["podman_socket"]
            )
            with PodmanClient(
                base_url=f"unix://{request.realm_data['podman_socket']}"
            ) as client:
                c = client.containers.get(container_name)
                if c.status in ["running", "starting"]:
                    return helpers.show_alert(
                        "genericError", "", 409, "Invalid status", f"Worker is running"
                    )
                c.remove()

        case "stop":
            container_name = listeners_helpers.get_container_name(
                listener_id, worker, request.realm_data["podman_socket"]
            )
            with PodmanClient(
                base_url=f"unix://{request.realm_data['podman_socket']}"
            ) as client:
                c = client.containers.get(container_name)
                c.stop()
                c.wait(condition="exited")

    return "", 204


@listeners.route("/<listener_id>", methods=["PATCH"])
@helpers.user_session_required
async def patch_listener(listener_id: str):
    req_body_dict = await request.json
    try:
        ListenerPatchModel = listeners_model.ListenerPatch(
            **req_body_dict, id=listener_id
        )
        listener_by_name = listeners_helpers.get_listener_by_name(
            name=ListenerPatchModel.name, realm_path=request.realm_data.get("path")
        )
        listener_by_id = listeners_helpers.get_listener_by_id(
            listener_id=ListenerPatchModel.id, realm_path=request.realm_data.get("path")
        )

        if listener_by_name and listener_by_name["id"] != ListenerPatchModel.id:
            return helpers.validation_error(
                [{"loc": ["name"], "msg": "Listener name does exist"}]
            )
        if not listener_by_id:
            return helpers.validation_error(
                [{"loc": [], "msg": "Listener ID does not exist"}]
            )

        _historic = listener_by_id["historic"]
        _historic = list(filter(None, _historic[: defaults.MAX_HISTORIC_REVISIONS]))
        _historic.append(listener_by_id["configuration"])

        ListenerPatchModel.historic = sorted(
            _historic, key=lambda d: d.get("revision"), reverse=True
        )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        db.table("listeners").update(
            ListenerPatchModel.dict(exclude_none=True, exclude={"id"}),
            (Query().id == ListenerPatchModel.id),
        )

    try:
        container_handler = Listener(
            listener_id=listener_id, realm_data=request.realm_data
        )
        container_handler.smtpd(command="create", ignore_exists=True)
    except Exception as e:
        return helpers.validation_error([{"loc": [], "msg": str(e)}])

    template = render_template(
        "listeners/partials/revisions.html",
        listener=listeners_helpers.get_listener_by_id(
            listener_id=listener_id, realm_path=request.realm_data.get("path")
        ),
    )
    return await template
