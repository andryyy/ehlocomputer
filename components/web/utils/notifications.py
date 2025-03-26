import json
from components.logs import logger


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
