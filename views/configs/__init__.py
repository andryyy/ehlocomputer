import json
import re
import sys
import traceback

from . import tools as configs_helpers
from config import defaults
from config.database import *
from models import configs as configs_model
from models import objects as objects_model
from pydantic import ValidationError
from quart import Blueprint, abort, render_template, request, session
from typing import Literal
from utils import helpers


async def render_or_json(tpl, headers, **context):
    if "application/json" in headers.get("Content-Type", ""):
        return next(filter(lambda x: x, context.values()))
    return await render_template(tpl, **context)


configs = Blueprint("configs", __name__, url_prefix="/configs")


@configs.route("/")
@helpers.user_session_required
async def root():
    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        config_table = db.table("configs")
        data = config_table.all()

    template = render_or_json("configs/configs.html", request.headers, data=data)
    return await template


@configs.route("/<config_id>")
@helpers.user_session_required
async def get_config(config_id: str):
    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        config = db.table("configs").get(Query().id == config_id)
        config["configuration"]["translated"] = configs_helpers.translate_raw_config(
            raw_config=config["configuration"].get("raw_config", {}),
            realm_path=request.realm_data.get("path"),
        )

    template = render_template("configs/config.html", config=config)
    return await template


@configs.route("/<config_id>/revision/<revision>")
@helpers.user_session_required
async def get_config_revision(config_id: str, revision: str):
    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        config = db.table("configs").get(Query().id == config_id)

    historic_config = next(
        (
            historic
            for historic in config.get("historic", [])
            if historic.get("revision") == revision
        ),
        {},
    )
    return configs_helpers.translate_raw_config(
        raw_config=historic_config.get("raw_config", {}),
        realm_path=request.realm_data.get("path"),
    )


@configs.route("/partials/select-objects/<object_type>")
@helpers.user_session_required
async def get_object_select_table(
    object_type: Literal["domains", "recipients", "settings"]
):
    if object_type == "domains":
        template = render_template(
            "configs/partials/domains.html", data={"object_type": object_type}
        )
    elif object_type == "recipients":
        template = render_template(
            "configs/partials/recipients.html", data={"object_type": object_type}
        )
    elif object_type == "settings":
        template = render_template(
            "configs/partials/settings.html", data={"object_type": object_type}
        )
    return await template


@configs.route("/<config_id>", methods=["DELETE"])
async def delete_config(config_id: str):
    try:
        config_by_id = configs_helpers.get_config_by_id(
            config_id=config_id, realm_path=request.realm_data.get("path")
        )
        if not config_by_id:
            return helpers.validation_error(
                [{"loc": ["id"], "msg": f"Config ID {config_id} does not exist"}]
            )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        config_table = db.table("configs")
        res = config_table.remove(
            (Query().id == config_id) & (Query().default == False)
        )
        if not res:
            return helpers.show_alert(
                "genericWarning",
                "",
                204,
                "Config not removed",
                f"Please verify the given config is not the current default",
            )

    return (
        "",
        200,
        {"HX-Location": json.dumps({"path": "/configs", "target": "#body-main"})},
    )


@configs.route("/", methods=["POST"])
@configs.route("/<config_id>", methods=["PATCH"])
@helpers.user_session_required
async def config_options(config_id: str | None = None):
    req_body_dict = await request.json

    configuration = {
        "raw_config": req_body_dict.get("raw_config", {}),
        "revision": helpers.utc_now_as_str(),
    }

    match request.method:
        case "POST":
            try:
                ConfigCreateModel = configs_model.ConfigCreate.parse_obj(req_body_dict)
                if configs_helpers.get_config_by_name(
                    name=ConfigCreateModel.name,
                    realm_path=request.realm_data.get("path"),
                ):
                    return helpers.validation_error(
                        [{"loc": ["name"], "msg": f"Config name exists"}]
                    )
            except ValidationError as e:
                return helpers.validation_error(e.errors())

            with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
                config_table = db.table("configs")
                config_table.insert(ConfigCreateModel.dict())

            template = render_template(
                "configs/partials/config_row.html",
                data={
                    "config_id": ConfigCreateModel.id,
                    "name": ConfigCreateModel.name,
                },
            )
            return await template

        case "PATCH":
            try:
                ConfigPatchModel = configs_model.ConfigPatch(
                    **req_body_dict, id=config_id, configuration=configuration
                )
                config_by_name = configs_helpers.get_config_by_name(
                    name=ConfigPatchModel.name,
                    realm_path=request.realm_data.get("path"),
                )
                config_by_id = configs_helpers.get_config_by_id(
                    config_id=config_id, realm_path=request.realm_data.get("path")
                )

                if not config_by_id:
                    return helpers.validation_error(
                        [
                            {
                                "loc": ["id"],
                                "msg": f"Config ID {config_id} does not exist",
                            }
                        ]
                    )

                if config_by_name and config_by_name["id"] != ConfigPatchModel.id:
                    return helpers.validation_error(
                        [{"loc": ["name"], "msg": "Config name exists"}]
                    )

                _historic = config_by_id["historic"]
                _historic = list(
                    filter(None, _historic[: defaults.MAX_HISTORIC_REVISIONS])
                )
                _historic.append(config_by_id["configuration"])

                ConfigPatchModel.historic = sorted(
                    _historic, key=lambda d: d.get("revision"), reverse=True
                )

            except ValidationError as e:
                return helpers.validation_error(e.errors())

            with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
                db.table("configs").update(
                    ConfigPatchModel.dict(exclude_none=True, exclude={"id"}),
                    Query().id == config_id,
                )

            config = ConfigPatchModel.dict()
            config["configuration"][
                "translated"
            ] = configs_helpers.translate_raw_config(
                raw_config=configuration["raw_config"],
                realm_path=request.realm_data.get("path"),
            )

            template = render_template("configs/partials/revisions.html", config=config)
            return await template
