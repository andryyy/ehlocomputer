from config.timezones import TIMEZONES
from email_validator import validate_email
from pydantic import AfterValidator, BaseModel, Field, field_validator
from pydantic_core import PydanticCustomError
from typing import Annotated
from utils.helpers import ensure_list, to_unique_sorted_str_list
from uuid import uuid4


class ObjectDomain(BaseModel):
    @field_validator("bcc_inbound", mode="before")
    def bcc_inbound_validator(cls, v):
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

    @field_validator("bcc_outbound", mode="before")
    def bcc_outbound_validator(cls, v):
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

    bcc_inbound: str = Field(
        default="",
        json_schema_extra={
            "title": "BCC inbound",
            "description": "BCC destination for incoming messages",
            "type": "email",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"bcc-inbound-{str(uuid4())}",
        },
    )

    bcc_outbound: str = Field(
        default="",
        json_schema_extra={
            "title": "BCC outbound",
            "description": "BCC destination for outbound messages",
            "type": "email",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"bcc-outbound-{str(uuid4())}",
        },
    )

    policies: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        default=[""],
        json_schema_extra={
            "title": "Policies",
            "description": "Policies for this domain.",
            "type": "select:multi",
            "options": [
                {"name": "-- Deny all", "value": ""},
                {"name": "Send", "value": "send"},
                {"name": "Receive", "value": "receive"},
                {"name": "Allow outbound", "value": "allow_outbound"},
                {"name": "System managed", "value": "system_managed"},
            ],
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"policies-{str(uuid4())}",
        },
    )

    policy_weight: str = Field(
        default="domain_mailbox",
        json_schema_extra={
            "title": "Policy weight",
            "description": "Policy override options.",
            "type": "select",
            "options": [
                {"name": "Domain > Mailbox", "value": "domain_mailbox"},
                {"name": "Mailbox > Domain", "value": "mailbox_domain"},
            ],
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"policy-weight-{str(uuid4())}",
        },
    )

    assigned_users: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        json_schema_extra={
            "title": "Assigned users",
            "description": "Assign this object to users.",
            "type": "users:multi",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"assigned-users-{str(uuid4())}",
        },
    )


class ObjectMailbox(BaseModel):
    mailbox: str = Field(
        default="",
        json_schema_extra={
            "title": "Mailbox",
            "description": "The left part of the email address (<mailbox>@domain)",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"mailbox-{str(uuid4())}",
        },
    )

    policies: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        default=[""],
        json_schema_extra={
            "title": "Policies",
            "description": "Policies for this mailbox.",
            "type": "select:multi",
            "options": [
                {"name": "-- Deny all", "value": ""},
                {"name": "Send", "value": "send"},
                {"name": "Receive", "value": "receive"},
                {"name": "Allow outbound", "value": "allow_outbound"},
                {"name": "System managed", "value": "system_managed"},
            ],
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"policies-{str(uuid4())}",
        },
    )

    assigned_object_groups: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        default=[],
        json_schema_extra={
            "title": "Assigned groups",
            "description": "Assign this mailbox to groups.",
            "type": "object_groups:multi",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"assigned-object-groups-{str(uuid4())}",
        },
    )

    assigned_users: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        json_schema_extra={
            "title": "Assigned users",
            "description": "Assign this object to users.",
            "type": "users:multi",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"assigned-users-{str(uuid4())}",
        },
    )


class ObjectGroup(BaseModel):
    @field_validator("start", mode="before")
    def start_date_validator(cls, v):
        try:
            start = v
        except:
            raise PydanticCustomError(
                "start_date_invalid",
                "The provided start date is invalid",
                dict(start=v),
            )
        return start

    @field_validator("end", mode="before")
    def end_date_validator(cls, v):
        try:
            end = v
        except:
            raise PydanticCustomError(
                "end_date_invalid",
                "The provided end date is invalid",
                dict(end=v),
            )
        return end

    tz: str = Field(
        default="",
        json_schema_extra={
            "title": "Timezone",
            "description": "The appointment's timezone.",
            "type": "datalist",
            "options": TIMEZONES,
            "input_extra": '_="init if my value is empty set my value to Intl.DateTimeFormat().resolvedOptions().timeZone end" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"activity-type-{str(uuid4())}",
        },
    )

    start: str = Field(
        default="",
        json_schema_extra={
            "title": "Start date",
            "description": "Start date of appointment",
            "type": "datetime-local",
            "input_extra": '_="init set my value to datetime_local(0) unless my value end" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"email-{str(uuid4())}",
        },
    )

    end: str = Field(
        default="",
        json_schema_extra={
            "title": "End date",
            "description": "End date of appointment",
            "type": "datetime-local",
            "input_extra": '_="init set my value to datetime_local(120) unless my value end" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"email-{str(uuid4())}",
        },
    )

    assigned_users: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        json_schema_extra={
            "title": "Assigned users",
            "description": "Assign this object to users.",
            "type": "users:multi",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"assigned-users-{str(uuid4())}",
        },
    )
