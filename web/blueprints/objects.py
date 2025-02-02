import re
from config.cluster import ClusterLock
from models.tables import TableSearchHelper
from models import objects as objects_model
from pydantic import ValidationError
from quart import Blueprint, current_app as app, render_template, request, session
from tools.users import search as search_users
from tools.objects import (
    create as _create_object,
    search as _search_object,
    delete as _delete_object,
    patch as _patch_object,
    get as _get_object,
)
from utils import wrappers
from utils.helpers import batch, ensure_list
from uuid import uuid4
from web.helpers import trigger_notification, validation_error, render_or_json

blueprint = Blueprint("objects", __name__, url_prefix="/objects")


@blueprint.context_processor
async def load_context():
    context = dict()
    context["system_fields"] = {
        object_type: system_fields
        for object_type, system_fields in objects_model.model_classes[
            "system_fields"
        ].items()
    }
    context["unique_fields"] = {
        object_type: unique_fields
        for object_type, unique_fields in objects_model.model_classes[
            "unique_fields"
        ].items()
    }
    context["schemas"] = {
        object_type: v.model_json_schema()
        for object_type, v in objects_model.model_classes["forms"].items()
    }
    return context


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
@wrappers.formoptions(["emailusers", "domains", "keypairs", "users"])
async def get_object(object_type: str, object_id: str):
    try:
        object_data = await _get_object(object_id=object_id, object_type=object_type)

        if not object_data:
            return (f"<h1>Object not found</h1><p>Object is unknown</p>", 404)

        """
        Inject form options not provided by user permission.
        A user will not be able to access detailed information about objects
        with inherited permission nor will they be able to remove assignments.
        """
        if object_type == "addresses":
            object_domain = {
                "name": object_data.details.assigned_domain.name,
                "value": object_data.details.assigned_domain.id,
            }
            if object_domain not in request.form_options["domains"]:
                object_domain["name"] = f"{object_data.details.assigned_domain.name} ⚠️"
                request.form_options["domains"].append(object_domain)

            for object_emailuser in object_data.details.assigned_emailusers:
                u = {
                    "name": object_emailuser.name,
                    "value": object_emailuser.id,
                }
                if u not in request.form_options["emailusers"]:
                    u["name"] = f"{object_emailuser.name} ⚠️"
                    request.form_options["emailusers"].append(u)

        elif object_type == "domains":
            object_keypair_injections = []
            for attr in ["assigned_dkim_keypair", "assigned_arc_keypair"]:
                object_keypair_details = getattr(object_data.details, attr)
                if hasattr(object_keypair_details, "id"):
                    object_keypair = {
                        "name": object_keypair_details.name,
                        "value": object_keypair_details.id,
                    }
                    if (
                        object_keypair not in request.form_options["keypairs"]
                        and object_keypair not in object_keypair_injections
                    ):
                        object_keypair_injections.append(object_keypair)
            for keypair in object_keypair_injections:
                keypair["name"] = keypair["name"] + " ⚠️"
                request.form_options["keypairs"].append(keypair)

    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    return await render_or_json(
        "objects/object.html", request.headers, object=object_data
    )


@blueprint.route("/<object_type>")
@blueprint.route("/<object_type>/search", methods=["POST"])
@wrappers.acl("user")
@wrappers.formoptions(["domains"])
async def get_objects(object_type: str):
    try:
        (
            search_model,
            page,
            page_size,
            sort_attr,
            sort_reverse,
            filters,
        ) = TableSearchHelper(
            request.form_parsed, object_type, default_sort_attr="name"
        )
    except ValidationError as e:
        return validation_error(e.errors())

    if request.method == "POST":
        try:
            match_any = {
                "key_name": search_model.q,
                "domain": search_model.q,
                "local_part": search_model.q,
                "username": search_model.q,
                "assigned_domain": search_model.q,
            }
            match_all = (
                {"assigned_users": [session["id"]]}
                if not "system" in session["acl"]
                else {}
            )
            matched_objects = await _search_object(
                object_type=object_type,
                match_any=match_any,
                fully_resolve=True,
                match_all=filters | match_all,
            )
        except ValidationError as e:
            return validation_error(e.errors())

        object_pages = [
            m
            for m in batch(
                sorted(
                    matched_objects,
                    key=lambda x: getattr(x, sort_attr),
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
            "objects/includes/objects/table_body.html",
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
        async with ClusterLock(object_type):
            object_id = await _create_object(
                object_type=object_type, data=request.form_parsed
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
        async with ClusterLock(object_type):
            deleted_objects = await _delete_object(
                object_id=object_ids, object_type=object_type
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
        title="Object removed",
        message=f"{len(deleted_objects)} object{'s' if len(deleted_objects) > 1 else ''} removed",
    )


@blueprint.route("/<object_type>/patch", methods=["POST"])
@blueprint.route("/<object_type>/<object_id>", methods=["PATCH"])
@wrappers.acl("user")
async def patch_object(object_type: str, object_id: str | None = None):
    if request.method == "POST":
        object_id = request.form_parsed.get("id")
    try:
        async with ClusterLock(object_type):
            patched_objects = await _patch_object(
                object_id=object_id, object_type=object_type, data=request.form_parsed
            )

    except ValidationError as e:
        return validation_error(e.errors())
    except ValueError as e:
        name, message = e.args
        return validation_error([{"loc": [name], "msg": message}])

    return trigger_notification(
        level="success" if len(patched_objects) > 0 else "warning",
        response_body="",
        response_code=204,
        title="Patch completed",
        message=f"{len(patched_objects)} object{'s' if (len(patched_objects) > 1 or len(patched_objects) == 0) else ''} modified",
    )
