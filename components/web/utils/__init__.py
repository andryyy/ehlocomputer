from .locking import *
from .quart import *
from .wrappers import *
from .notifications import *
from config import defaults
from components.database import IN_MEMORY_DB
from components.models.tables import TableSearch, BaseModel
from components.users import search as search_users


def table_search_helper(
    body, session_key_identifier, default_sort_attr, default_sort_reverse: bool = False
):
    search_model = TableSearch.parse_obj(body or {})
    search_model_post = search_model.dict(exclude_unset=True)

    # Post wins over session wins over default
    page = search_model_post.get(
        "page", session.get(f"{session_key_identifier}_page", search_model.page)
    )
    page_size = search_model_post.get(
        "page_size",
        session.get(f"{session_key_identifier}_page_size", search_model.page_size),
    )
    filters = search_model_post.get(
        "filters",
        session.get(f"{session_key_identifier}_filters", search_model.filters),
    )
    sorting = search_model_post.get(
        "sorting",
        session.get(
            f"{session_key_identifier}_sorting",
            (default_sort_attr, default_sort_reverse),
        ),
    )
    sort_attr, sort_reverse = sorting

    session.update(
        {
            f"{session_key_identifier}_page": page,
            f"{session_key_identifier}_page_size": page_size,
            f"{session_key_identifier}_sorting": sorting,
            f"{session_key_identifier}_filters": filters,
        }
    )

    return search_model, page, page_size, sort_attr, sort_reverse, filters


def parse_form_to_dict(key, value):
    keys = key.split(".")
    nested_dict = {}
    current_level = nested_dict

    for key in keys[:-1]:
        current_level = current_level.setdefault(key, {})

    current_level[keys[-1]] = value
    return nested_dict


async def ws_htmx(
    channel, strategy: str, data, if_path: str = "", exclude_self: bool = False
):
    if channel.startswith("_") and channel in [f"_{acl}" for acl in defaults.USER_ACLS]:
        matched_users = [
            m.login
            for m in await search_users(name="")
            if channel.removeprefix("_") in m.acl
        ]
        if matched_users:
            for user in matched_users:
                await ws_htmx(user, strategy, data, if_path, exclude_self)

    for ws, ws_data in IN_MEMORY_DB["WS_CONNECTIONS"].get(channel, {}).items():
        if exclude_self and ws.cookies == request.cookies:
            continue
        if not if_path or ws_data.get("path", "").startswith(if_path):
            await ws.send(f'<div id="ws-recv" hx-swap-oob="{strategy}">{data}</div>')


async def render_or_json(tpl, headers, **context):
    if "application/json" in headers.get("Content-Type", ""):

        def convert_to_dict(value):
            return (
                value.model_dump(mode="json") if isinstance(value, BaseModel) else value
            )

        converted_context = {
            key: convert_to_dict(value) for key, value in context.items()
        }

        return next(filter(lambda x: x, converted_context.values()), dict())

    return await render_template(tpl, **context)
