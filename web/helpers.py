import json

from config import defaults
from config.logs import logger
from copy import deepcopy
from pydantic import constr, validate_call
from quart import current_app as app, render_template, session, websocket
from tools.users import Users
from typing import Literal


def merge_deep(dict1, dict2):
    result = deepcopy(dict1)

    def _recursive_merge(_dict1, _dict2):
        for key in _dict2:
            if (
                key in _dict1
                and isinstance(_dict1[key], dict)
                and isinstance(_dict2[key], dict)
            ):
                _recursive_merge(_dict1[key], _dict2[key])
            else:
                _dict1[key] = _dict2[key]

    _recursive_merge(result, dict2)
    return result


@validate_call
def parse_form_to_dict(key, value):
    keys = key.split(".")
    nested_dict = {}
    current_level = nested_dict

    for key in keys[:-1]:
        current_level = current_level.setdefault(key, {})

    current_level[keys[-1]] = value
    return nested_dict


@validate_call
async def ws_htmx(channel, strategy: str, data, if_path: str = ""):
    if channel in defaults.USER_ACLS:
        matched_users = [
            m.login for m in await Users().search(q="") if channel in m.acl
        ]
        if matched_users:
            for user in matched_users:
                await ws_htmx(user, strategy, data, if_path)

    for ws, path in app.config["WS_CONNECTIONS"].get(channel, {}).items():
        if not if_path or path.startswith(if_path):
            await ws.send(f'<div id="ws-recv" hx-swap-oob="{strategy}">{data}</div>')


async def render_or_json(tpl, headers, **context):
    if "application/json" in headers.get("Content-Type", ""):
        return next(filter(lambda x: x, context.values()))
    return await render_template(tpl, **context)


@validate_call
def session_clear(preserved_keys: list = []) -> None:
    if not preserved_keys:
        preserved_keys = defaults.PRESERVE_SESSION_KEYS

    restore_keys = set()

    for k in preserved_keys:
        session_key = session.get(k)
        if session_key:
            restore_keys.add(
                (k, session_key),
            )

    session.clear()

    for k in restore_keys:
        session[k[0]] = k[1]


@validate_call
def trigger_notification(
    level: Literal["error", "warning", "success", "user", "system"],
    response_body: str,
    response_code: int,
    title: str,
    message: str,
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


@validate_call
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
