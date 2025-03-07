import json
from .locking import *
from .quart import *
from .wrappers import *
from config import defaults
from components.database import IN_MEMORY_DB
from components.logs import logger
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


async def ws_htmx(channel, strategy: str, data, if_path: str = ""):
    if channel in defaults.USER_ACLS:
        matched_users = [
            m.login for m in await search_users(name="") if channel in m.acl
        ]
        if matched_users:
            for user in matched_users:
                await ws_htmx(user, strategy, data, if_path)

    for ws, path in IN_MEMORY_DB["WS_CONNECTIONS"].get(channel, {}).items():
        if not if_path or path.startswith(if_path):
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


def trigger_notification(
    level: str,  # "error", "warning", "success", "user", "system"
    response_code: int,
    title: str,
    message: str,
    response_body: str = "",
    duration: int = 7000,
    additional_triggers: dict = {},
):
    logger_payload = {
        "level": level,
        "response_code": response_code,
        "title": title,
        "message": message,
        "additional_triggers": additional_triggers,
    }

    if level in ["system", "user"]:
        logger_method = getattr(logger, "info")
    else:
        logger_method = getattr(logger, level)

    logger_method(logger_payload)

    return (
        response_body,
        response_code,
        {
            "HX-Retarget": "body",
            "HX-Trigger": json.dumps(
                {
                    "notification": {
                        "level": level,
                        "title": title,
                        "message": message,
                        "duration": duration,
                    },
                    **additional_triggers,
                }
            ),
        },
    )


def validation_error(
    errors: list = [], response_code: int = 422, message: str | None = None
):
    locations = []
    if errors:
        for loc in [l.get("loc") for l in errors if l.get("loc")]:
            i = 1
            _location = None
            if len(loc) > 1:
                while len(loc) > i:
                    if not _location:
                        if not "[" in loc[1]:
                            _location = f"{loc[0]}.{loc[1]}"
                        else:
                            _location = f"{loc[0]}"
                        i = 2
                    else:
                        if not "[" in str(loc[i]):
                            # Remove locations that are also specified with an index
                            # This prevents highlighting
                            if isinstance(loc[i], int) and _location in locations:
                                locations.remove(_location)
                            _location = f"{_location}.{loc[i]}"
                        i += 1
                locations.append(_location)
            else:
                if isinstance(loc, tuple) or isinstance(loc, list):
                    locations.append(loc[0])
                elif isinstance(loc, str):
                    locations.append(loc)

        error_msgs = list(
            set(
                l.get("msg").removeprefix("Value error, ")
                for l in errors
                if l.get("msg")
            )
        )
        if not error_msgs:
            error_msgs = ["Provided data could not be validated"]

    if message:
        error_msgs = [message]

    logger.error(
        {
            "level": "validationError",
            "errors": errors,
            "response_code": response_code,
            "error_msgs": error_msgs,
        }
    )

    return (
        "",
        response_code,
        {
            "HX-Retarget": "body",
            "HX-Trigger": json.dumps(
                {
                    "notification": {
                        "level": "validationError",
                        "locations": locations,
                        "message": error_msgs,
                        "duration": 7000,
                    }
                }
            ),
        },
    )
