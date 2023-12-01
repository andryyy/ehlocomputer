import json
import os

from . import tools as realms_helpers
from config import defaults
from config.database import r
from config.database import JSONStorage
from config.database import Query
from config.database import RedisLockMiddleware
from config.database import TinyDB
from models import realms as realms_model
from pydantic import ValidationError
from quart import Blueprint, abort, redirect, render_template, request, session, url_for
from typing import Literal
from utils import helpers
from utils import crypto


realms = Blueprint("realms", __name__, url_prefix="/realms")


@realms.route("/", methods=["GET"])
@helpers.user_session_required
async def root():
    with TinyDB(
        **{
            "storage": RedisLockMiddleware(JSONStorage),
            "path": "realms/realms.json",
            "sort_keys": True,
            "indent": 2,
        }
    ) as db:
        realms_table = db.table("realms")
        realms = realms_table.all()

    template = render_template(
        "realms/realms.html",
        data={"realms": realms},
    )

    return await template


@realms.route("/<realm_id>", methods=["GET"])
@helpers.user_session_required
async def get_realm(realm_id: str):
    with TinyDB(
        **{
            "storage": RedisLockMiddleware(JSONStorage),
            "path": "realms/realms.json",
            "sort_keys": True,
            "indent": 2,
        }
    ) as db:
        realms_table = db.table("realms")
        data = realms_table.search(Query().id == realm_id)

    if not data:
        abort(404)

    template = render_template("realms/realm.html", realm=data.pop())
    return await template


@realms.route("/<realm_id>/add-neighbour", methods=["GET"])
@helpers.user_session_required
async def add_neighbour(realm_id: str):
    private_key, public_key = crypto.rsa_generate_keypair()
    template = render_template(
        "realms/partials/neighbour.html",
        data={"private_key": private_key, "public_key": public_key},
    )
    return await template


@realms.route("/", methods=["POST"])
@helpers.user_session_required
async def create_realm():
    req_body_dict = await request.json
    try:
        RealmCreateModel = realms_model.RealmCreate.parse_obj(req_body_dict)
        if realms_helpers.get_realm_by_name(name=RealmCreateModel.name):
            return helpers.validation_error(
                [{"loc": ["name"], "msg": "Realm name does exist"}]
            )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(
        **{
            "storage": RedisLockMiddleware(JSONStorage),
            "path": "realms/realms.json",
            "sort_keys": True,
            "indent": 2,
        }
    ) as db:
        realms_table = db.table("realms")
        realms_table.insert(RealmCreateModel.dict())
        with TinyDB(f"realms/databases/{RealmCreateModel.id}") as c:
            pass

    template = render_template(
        "realms/partials/realm_row.html",
        data={"realm_id": RealmCreateModel.id, "name": RealmCreateModel.name},
    )
    return await template


@realms.route("/<realm_id>", methods=["DELETE"])
@helpers.user_session_required
async def delete_realm(realm_id: str):
    req_body_dict = await request.json
    try:
        realm_by_id = realms_helpers.get_realm_by_id(realm_id=realm_id)
        if not realm_by_id:
            return helpers.validation_error(
                [{"loc": ["name"], "msg": "Realm name does not exist"}]
            )
        r.delete(f"realmdata:{realm_by_id['origin']}")

    except ValidationError as e:
        return helpers.validation_error(e.errors())
    except FileNotFoundError as e:
        pass

    with TinyDB(
        **{
            "storage": RedisLockMiddleware(JSONStorage),
            "path": "realms/realms.json",
            "sort_keys": True,
            "indent": 2,
        }
    ) as db:
        realms_table = db.table("realms")
        res = realms_table.remove((Query().id == realm_id) & (Query().default == False))
        if not res:
            return helpers.show_alert(
                "genericWarning",
                "",
                204,
                "Realm not removed",
                f"Please verify the given realm is not the current default",
            )

    return (
        "",
        200,
        {"HX-Location": json.dumps({"path": "/realms", "target": "#body-main"})},
    )


@realms.route("/bootstrap/<realm_id>", methods=["PATCH"])
async def first_realm_patch(realm_id: str):
    req_body_dict = await request.json
    if req_body_dict.get("bootstrap_token") and r.getdel(
        "setup_realm:bootstraptoken"
    ) == req_body_dict.get("bootstrap_token"):
        with TinyDB(path="realms/realms.json") as db:
            if db.table("realms").get(Query().bootstrapped == True):
                abort(404)

        r.delete(f"realmdata:{request.headers.get('Host')}")
        try:
            req_body_dict.update({"id": realm_id})
            RealmPatchModel = realms_model.RealmPatch.parse_obj(req_body_dict)
        except ValidationError as e:
            return helpers.validation_error(e.errors())

        with TinyDB(
            **{
                "storage": RedisLockMiddleware(JSONStorage),
                "path": "realms/realms.json",
                "sort_keys": True,
                "indent": 2,
            }
        ) as db:
            db.table("realms").update(
                RealmPatchModel.dict(exclude_none=True, exclude={"id"}),
                Query().id == RealmPatchModel.id,
            )

        return "", 200, {"HX-Refresh": True, "HX-Redirect": "/"}


@realms.route("/<realm_id>", methods=["PATCH"])
@helpers.user_session_required
async def patch_realm(realm_id: str):
    req_body_dict = await request.json
    try:
        req_body_dict.update({"id": realm_id})
        RealmPatchModel = realms_model.RealmPatch.parse_obj(req_body_dict)
        realm_by_name = realms_helpers.get_realm_by_name(name=RealmPatchModel.name)
        realm_by_id = realms_helpers.get_realm_by_id(realm_id=RealmPatchModel.id)

        r.delete(f"realmdata:{realm_by_id['origin']}")
        if realm_by_name and realm_by_name["id"] != RealmPatchModel.id:
            return helpers.validation_error(
                [{"loc": ["name"], "msg": "Realm name does exist"}]
            )
        if not realm_by_id:
            return helpers.validation_error(
                [{"loc": [], "msg": "Realm ID does not exist"}]
            )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(
        **{
            "storage": RedisLockMiddleware(JSONStorage),
            "path": "realms/realms.json",
            "sort_keys": True,
            "indent": 2,
        }
    ) as db:
        realms_table = db.table("realms")
        realms_table.update(
            RealmPatchModel.dict(exclude_none=True, exclude={"id"}),
            Query().id == RealmPatchModel.id,
        )
        print(db.table("realms").all())
        if RealmPatchModel.default:
            realms_table.update({"default": False}, Query().id != RealmPatchModel.id)

        return helpers.show_alert(
            "genericSuccess",
            "",
            204,
            "Realm modified",
            "Realm was successfully modified",
        )
