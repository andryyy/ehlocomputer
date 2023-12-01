import json
import sys
import traceback

from . import tools as objects_helpers
from config import defaults, settings
from config.database import *
from models import objects as objects_model
from pydantic import ValidationError
from quart import Blueprint, render_template, request, session
from utils import helpers
from uuid import uuid4


objects = Blueprint("objects", __name__, url_prefix="/objects")


@objects.context_processor
def settings_rules():
    return dict(
        SETTINGS_DATA={
            k: v | dict({"id": k}) for k, v in settings.SETTINGS_DATA.items()
        },
        SETTINGS_CATEGORIES=settings.SETTINGS_CATEGORIES,
    )


@objects.route("/")
@helpers.user_session_required
async def root():
    template = render_template("objects/objects.html")
    return await template


@objects.route("/settings/<object_id>")
@objects.route("/settings/<object_id>/<setting_id>")
@helpers.user_session_required
async def get_settings(object_id: str, setting_id: int | None = None):
    try:
        if not objects_helpers.get_object_by_id(
            object_type="settings",
            object_id=object_id,
            realm_path=request.realm_data.get("path"),
        ):
            return helpers.validation_error(
                [{"loc": ["id"], "msg": f"Object ID does not exist"}]
            )
    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        object_table = db.table("settings")
        _object = object_table.get(Query().id == object_id)
        compareables = object_table.search(Query().source.any)

    tpl = "objects/setting.html"
    if setting_id:
        tpl = "objects/partials/setting.html"

    template = render_template(
        tpl,
        data={
            "object": _object,
            "compareables": compareables,
        },
    )

    return await template


@objects.route("/<object_type>")
@objects.route("/<object_type>/search", methods=["POST"])
@helpers.user_session_required
async def get_objects(object_type: str):
    req_body_dict = await request.json
    chunk = 1
    page_size = defaults.TABLE_PAGE_SIZE

    if req_body_dict and req_body_dict.get("chunk"):
        session[f"{object_type}_chunk"] = int(req_body_dict.get("chunk"))
    if req_body_dict and req_body_dict.get("page_size"):
        session[f"{object_type}_page_size"] = int(req_body_dict.get("page_size"))
    if f"{object_type}_chunk" in session:
        chunk = session[f"{object_type}_chunk"]
    if f"{object_type}_page_size" in session:
        page_size = session[f"{object_type}_page_size"]

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        object_table = db.table(object_type)
        if request.method == "POST":
            try:
                ObjectSearchModel = objects_model.ObjectSearch.parse_obj(req_body_dict)
            except ValidationError as e:
                return helpers.validation_error(e.errors())
            _objects = object_table.search(Query().name.search(ObjectSearchModel.q))
        else:
            _objects = object_table.all()

        object_chunks = [m for m in helpers.batch(_objects, page_size)]

        try:
            object_chunks[chunk - 1]
        except IndexError:
            chunk = len(object_chunks)

        objects = object_chunks[chunk - 1] if chunk else object_chunks

        if request.method == "POST":
            tpl = f"objects/partials/objects_table_body.html"
        else:
            tpl = f"objects/object.html"

        template = await render_template(
            tpl,
            data={
                "objects": objects,
                "object_type": object_type,
                "page_size": page_size,
                "chunk": chunk,
                "chunks": len(object_chunks) + 1,
                "elements": len(_objects),
            },
        )
    return template


@objects.route("/<object_type>", methods=["POST"])
@helpers.user_session_required
async def create_object(object_type: str):
    req_body_dict = await request.json

    try:
        req_body_dict.update(
            {
                "id": str(uuid4()),  # Generating object_id
            }
        )

        match object_type:
            case "domains":
                ObjectCreateModel = objects_model.ObjectCreateDomain.parse_obj(
                    req_body_dict
                )
            case "recipients":
                ObjectCreateModel = objects_model.ObjectCreateRecipient.parse_obj(
                    req_body_dict
                )
            case "settings":
                ObjectCreateModel = objects_model.ObjectCreateSetting.parse_obj(
                    req_body_dict
                )

        if objects_helpers.get_object_by_name(
            object_type=object_type,
            name=ObjectCreateModel.name,
            realm_path=request.realm_data.get("path"),
        ):
            return helpers.validation_error(
                [{"loc": ["name"], "msg": f"Object name exists"}]
            )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        object_table = db.table(object_type)
        object_table.insert(ObjectCreateModel.dict())

    return helpers.show_alert(
        "genericSuccess", "", 204, "Object created", "Object was created"
    )


@objects.route("/<object_type>/delete", methods=["POST"])
@objects.route("/<object_type>/<object_id>", methods=["DELETE"])
async def delete_object(object_type: str, object_id: str | None = None):
    req_body_dict = await request.json
    try:
        if request.method == "DELETE" and object_id:
            req_body_dict.update({"object_id": object_id})

        ObjectDeleteModel = objects_model.ObjectDelete.parse_obj(req_body_dict)
        for object_id in ObjectDeleteModel.id:
            if not objects_helpers.get_object_by_id(
                object_type=object_type,
                object_id=object_id,
                realm_path=request.realm_data.get("path"),
            ):
                return helpers.validation_error(
                    [{"loc": ["id"], "msg": f"Object ID {object_id} does not exist"}]
                )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        object_table = db.table(object_type)
        objects = object_table.search(Query().id.one_of(ObjectDeleteModel.id))
        object_table.remove(doc_ids=[o.doc_id for o in objects])

    return helpers.show_alert(
        "genericSuccess",
        "",
        204,
        "Object removed",
        f"Object{'s' if len(ObjectDeleteModel.id)>1 else ''} removed",
    )


@objects.route("/<object_type>/patch", methods=["POST"])
@objects.route("/<object_type>/<object_id>", methods=["PATCH"])
async def patch_object(object_type: str, object_id: str | None = None):
    req_body_dict = await request.json
    try:
        if request.method == "PATCH" and object_id:
            req_body_dict.update({"id": object_id})

        match object_type:
            case "domains":
                ObjectPatchModel = objects_model.ObjectPatchDomains.parse_obj(
                    req_body_dict
                )
            case "recipients":
                ObjectPatchModel = objects_model.ObjectPatchRecipients.parse_obj(
                    req_body_dict
                )
            case "settings":
                ObjectPatchModel = objects_model.ObjectPatchSettings.parse_obj(
                    req_body_dict
                )

        # name must be unique within type
        if ObjectPatchModel.name:
            if len(ObjectPatchModel.id) > 1:
                return helpers.validation_error(
                    [
                        {
                            "loc": ["name"],
                            "msg": "Unique attribute cannot be set for multiple objects",
                        }
                    ]
                )

            object_by_name = objects_helpers.get_object_by_name(
                object_type=object_type,
                name=ObjectPatchModel.name,
                realm_path=request.realm_data.get("path"),
            )
            if object_by_name and object_by_name["id"] != ObjectPatchModel.id[0]:
                return helpers.validation_error(
                    [{"loc": ["name"], "msg": "Object name exists"}]
                )

        for object_id in ObjectPatchModel.id:
            if not objects_helpers.get_object_by_id(
                object_type=object_type,
                object_id=object_id,
                realm_path=request.realm_data.get("path"),
            ):
                return helpers.validation_error(
                    [{"loc": ["id"], "msg": f"Object ID {object_id} does not exist"}]
                )

    except ValidationError as e:
        return helpers.validation_error(e.errors())

    with TinyDB(**defaults.TINYDB, path=request.realm_data.get("path")) as db:
        object_table = db.table(object_type)
        # Update object and exclude static fields
        object_table.update(
            ObjectPatchModel.dict(
                exclude_none=True, exclude_unset=True, exclude={"id"}
            ),
            Query().id.one_of(ObjectPatchModel.id),
        )

        return helpers.show_alert(
            "genericSuccess",
            "",
            204,
            "Object modified",
            "Object was successfully modified",
        )
