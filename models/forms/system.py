import re
from pydantic import (
    AfterValidator,
    BeforeValidator,
    BaseModel,
    Field,
    IPvAnyAddress,
    field_validator,
)
from pydantic_core import PydanticCustomError
from typing import Annotated, Literal
from uuid import uuid4
from config import defaults


class SystemSettingsForm(BaseModel):
    @field_validator("ACCEPT_LANGUAGES", mode="before")
    def languages(cls, v):
        if v in [None, ""]:
            return ["en"]
        for lang in v:
            if lang not in ["en", "de"]:
                raise PydanticCustomError(
                    "language_invalid",
                    "The provided language code is invalid",
                    dict(provided_language=v),
                )
        return v

    @field_validator("LOG_FILE_ROTATION", mode="before")
    def log_file_rotation(cls, v):
        pattern = r"^\d{1} days$"  # Matches a single digit followed by " days"
        if not bool(re.match(pattern, v)):
            raise PydanticCustomError(
                "log_file_rotation_invalid",
                "The provided string is invalid",
                dict(provided_language=v),
            )
        return v

    ACCEPT_LANGUAGES: Annotated[
        list[str],
        AfterValidator(lambda x: [x] if not isinstance(x, list) else x),
    ] = Field(
        min_length=1,
        default=defaults.ACCEPT_LANGUAGES,
        json_schema_extra={
            "title": "Accepted languages",
            "description": "Accepted languages by the clients browser.",
            "type": "list:text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"accept-languages-{str(uuid4())}",
        },
    )

    CLUSTER_PEERS_THEM: Annotated[
        list[IPvAnyAddress],
        AfterValidator(
            lambda x: [str(x)] if not isinstance(x, list) else [str(s) for s in x]
        ),
    ] = Field(
        min_length=0,
        default=defaults.CLUSTER_PEERS_THEM,
        json_schema_extra={
            "title": "Cluster peers",
            "description": "Other peers in cluster. Must not include the local address.",
            "type": "list:text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" readonly',
            "form_id": f"cluster-peers-them-{str(uuid4())}",
        },
    )

    CLUSTER_PEERS_ME: Annotated[
        IPvAnyAddress,
        AfterValidator(lambda x: str(x)),
    ] = Field(
        default=defaults.CLUSTER_PEERS_ME,
        json_schema_extra={
            "title": "Cluster address",
            "description": "This nodes cluster address bound to port 2102",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" readonly',
            "form_id": f"cluster-peers-me-{str(uuid4())}",
        },
    )

    AUTH_REQUEST_TIMEOUT: int = Field(
        default=defaults.AUTH_REQUEST_TIMEOUT,
        json_schema_extra={
            "title": "Proxy timeout",
            "description": "Proxy authentication timeout",
            "type": "number",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"proxy-auth-timeout-{str(uuid4())}",
        },
    )

    TABLE_PAGE_SIZE: int = Field(
        default=defaults.TABLE_PAGE_SIZE,
        json_schema_extra={
            "title": "Table page size",
            "description": "Default table page size",
            "type": "number",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"table-page-size-{str(uuid4())}",
        },
    )

    LOG_FILE_RETENTION: int = Field(
        default=defaults.LOG_FILE_RETENTION,
        json_schema_extra={
            "title": "Log file retention",
            "description": "Number of log files to keep after each rotation",
            "type": "number",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"log-file-retention-{str(uuid4())}",
        },
    )

    LOG_FILE_ROTATION: str = Field(
        default=defaults.LOG_FILE_ROTATION,
        json_schema_extra={
            "title": "Log file rotation",
            "description": "Log file rotation in the format <code>n days</code>",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"log-file-retention-{str(uuid4())}",
        },
    )

    TEMPLATES_AUTO_RELOAD: Annotated[
        Literal[True, False],
        BeforeValidator(lambda x: True if str(x).lower() == "true" else False),
        AfterValidator(lambda x: True if str(x).lower() == "true" else False),
    ] = Field(
        default=defaults.TEMPLATES_AUTO_RELOAD,
        json_schema_extra={
            "title": "Reload templates",
            "description": "Automatically reload templates on change",
            "type": "radio",
            "input_extra": 'autocomplete="off"',
            "form_id": f"templats-auto-reload-{str(uuid4())}",
        },
    )
