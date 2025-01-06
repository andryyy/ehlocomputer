from config.defaults import ACCESS_TOKEN_FORMAT
from email_validator import validate_email
from pydantic import (
    AfterValidator,
    BeforeValidator,
    BaseModel,
    Field,
    field_validator,
    ConfigDict,
)
from pydantic_core import PydanticCustomError
from typing import Annotated, Literal
from utils.helpers import ensure_list, to_unique_sorted_str_list
from uuid import uuid4


class UserProfile(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    @field_validator("email", mode="before")
    def email_validator(cls, v):
        if v in [None, ""]:
            return ""
        try:
            email = validate_email(v, check_deliverability=False).ascii_email
        except:
            raise PydanticCustomError(
                "email_invalid",
                "The provided email address is invalid",
                dict(provided_email=v),
            )
        return email

    email: str = Field(
        default="",
        json_schema_extra={
            "title": "Email address",
            "description": "Your email address is optional",
            "type": "email",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"email-{str(uuid4())}",
        },
    )

    access_tokens: Annotated[
        ACCESS_TOKEN_FORMAT | list[ACCESS_TOKEN_FORMAT],
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        default=[],
        json_schema_extra={
            "title": "Access tokens",
            "description": "Tokens to access the API. Save profile after removing a token.",
            "type": "list:text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"access-tokens-{str(uuid4())}",
        },
    )

    permit_auth_requests: Annotated[
        Literal[True, False],
        BeforeValidator(lambda x: True if str(x).lower() == "true" else False),
        AfterValidator(lambda x: True if str(x).lower() == "true" else False),
    ] = Field(
        default=True,
        json_schema_extra={
            "title": "Authentication requests",
            "description": "Allow other devices to issue authentication requests to active sessions via pop-up",
            "type": "radio",
            "input_extra": 'autocomplete="off"',
            "form_id": f"proxy-login-{str(uuid4())}",
        },
    )
