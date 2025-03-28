from config import defaults
from components.utils import ensure_list
from components.utils.datetimes import utc_now_as_str
from components.models import *


class SystemSettings(BaseModel):
    ACCEPT_LANGUAGES: Annotated[
        list[Literal["en", "de"]],
        BeforeValidator(lambda x: ensure_list(x)),
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

    LOG_FILE_ROTATION: int = Field(
        default=defaults.LOG_FILE_ROTATION,
        json_schema_extra={
            "title": "Max size in bytes",
            "description": "Log files will rotate after given bytes",
            "type": "number",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"log-file-rotation-{str(uuid4())}",
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


class SystemSettingsBase(BaseModel):
    details: SystemSettings = SystemSettings()


class UpdateSystemSettings(SystemSettingsBase):
    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()
