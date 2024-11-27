from email_validator import validate_email
from pydantic import AfterValidator, BaseModel, Field, field_validator
from pydantic_core import PydanticCustomError
from typing import Annotated
from utils.helpers import ensure_list, to_unique_sorted_str_list
from uuid import uuid4


class ObjectPatchContactForm(BaseModel):
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

    activity_type: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        default=[],
        json_schema_extra={
            "title": "Activity type",
            "description": "Activity to fit the object.",
            "type": "select:multi",
            "options": [
                {"name": "Running (outdoor)", "value": "running_outdoor"},
                {"name": "Running (indoor)", "value": "running_indoor"},
                {"name": "Cycling", "value": "cycling"},
            ],
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"activity-type-{str(uuid4())}",
        },
    )

    assigned_users: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        default=[],
        json_schema_extra={
            "title": "Assigned users",
            "description": "Assign this object to users.",
            "type": "users:multi",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"assigned-users-{str(uuid4())}",
        },
    )


class ObjectPatchCalendarForm(BaseModel):
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


class ObjectPatchAppointmentForm(BaseModel):
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
