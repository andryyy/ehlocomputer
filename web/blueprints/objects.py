import re

from config.cluster import cluster
from models.tables import TableSearchHelper
from models import objects as objects_model
from pydantic import ValidationError
from quart import Blueprint, current_app as app, render_template, request
from tools.users import Users
from tools.objects import Objects
from utils import wrappers
from utils.helpers import batch, ensure_list
from uuid import uuid4
from web.helpers import trigger_notification, validation_error

blueprint = Blueprint("objects", __name__, url_prefix="/objects")


@blueprint.context_processor
async def load_schemas():
    schemas = {
        f"_{object_type}_schema": v.model_json_schema()
        for object_type, v in objects_model.model_classes["forms"].items()
    }
    return {
        "schemas": schemas,
        # injects user_options if route endpoint == "objects.get_object" to allow selecting users in object form
        "user_options": [
            {"name": user.login, "value": user.id}
            for user in await Users().search(q="")
        ]
        if request.endpoint == "objects.get_object"
        else [],
    }


@blueprint.before_request
async def objects_before_request():
    if "object_type" in request.view_args:
        if request.view_args["object_type"] not in objects_model.model_classes["types"]:
            if "Hx-Request" in request.headers:
                return trigger_notification(
                    level="error",
                    response_body="",
                    response_code=204,
                    title="Object type error",
                    message="Object type is unknown",
                )
            else:
                return (f"<h1>Object type error</h1><p>Object type is unknown</p>", 409)


@blueprint.route("/<object_type>/<object_id>")
@wrappers.acl("user")
async def get_object(object_type: str, object_id: str):
    try:
        object_data = await Objects.object(id=object_id, object_type=object_type).get()
    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    return await render_template(f"objects/object.html", object=object_data.dict())


@blueprint.route("/<object_type>")
@blueprint.route("/<object_type>/search", methods=["POST"])
@wrappers.acl("user")
async def get_objects(object_type: str):
    try:
        search_model, page, page_size, sort_attr, sort_reverse = TableSearchHelper(
            request.form_parsed, object_type, default_sort_attr="name"
        )
    except ValidationError as e:
        return validation_error(e.errors())

    if request.method == "POST":
        try:
            matched_objects = [
                m.dict()
                for m in await Objects().search(
                    object_type=object_type, q=search_model.q
                )
            ]
        except ValidationError as e:
            return validation_error(e.errors())

        object_pages = [
            m
            for m in batch(
                sorted(
                    matched_objects,
                    key=lambda x: x.get(sort_attr, "id"),
                    reverse=sort_reverse,
                ),
                page_size,
            )
        ]

        try:
            object_pages[page - 1]
        except IndexError:
            page = len(object_pages)

        objects = object_pages[page - 1] if page else object_pages

        return await render_template(
            "objects/includes/table_body.html",
            data={
                "objects": objects,
                "page_size": page_size,
                "page": page,
                "pages": len(object_pages),
                "elements": len(matched_objects),
            },
        )
    else:
        return await render_template(
            "objects/objects.html", data={"object_type": object_type}
        )


@blueprint.route("/<object_type>", methods=["POST"])
@wrappers.acl("user")
async def create_object(object_type: str):
    try:
        async with cluster:
            object_id = await Objects.object(object_type=object_type).create(
                data=request.form_parsed
            )
    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    return trigger_notification(
        level="success",
        response_body="",
        response_code=204,
        title="Object created",
        message=f"Object {object_id} created",
    )


@blueprint.route("/<object_type>/delete", methods=["POST"])
@blueprint.route("/<object_type>/<object_id>", methods=["DELETE"])
@wrappers.acl("user")
async def delete_object(object_type: str, object_id: str | None = None):
    if request.method == "POST":
        object_id = request.form_parsed.get("id")
    try:
        object_ids = ensure_list(object_id)
        async with cluster:
            await Objects.object(id=object_ids, object_type=object_type).delete()

    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    return trigger_notification(
        level="success",
        response_body="",
        response_code=204,
        title="Object removed",
        message=f"{len(object_ids)} object{'s' if len(object_ids) > 1 else ''} removed",
    )


@blueprint.route("/<object_type>/patch", methods=["POST"])
@blueprint.route("/<object_type>/<object_id>", methods=["PATCH"])
@wrappers.acl("user")
async def patch_object(object_type: str, object_id: str | None = None):
    if request.method == "POST":
        object_id = request.form_parsed.get("id")
    try:
        async with cluster:
            await Objects.object(id=object_id, object_type=object_type).patch(
                data=request.form_parsed
            )

    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    return trigger_notification(
        level="success",
        response_body="",
        response_code=204,
        title="Object modified",
        message=f"Object data modified",
    )
