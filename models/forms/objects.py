import email_validator

from config.timezones import TIMEZONES
from pydantic import (
    AfterValidator,
    BeforeValidator,
    BaseModel,
    Field,
    field_validator,
    conint,
    constr,
    computed_field,
    model_validator,
    ConfigDict,
    PrivateAttr,
)
from pydantic_core import PydanticCustomError
from typing import Annotated, Literal, Any
from typing_extensions import Self
from utils.helpers import ensure_list, to_unique_sorted_str_list
from uuid import uuid4

email_validator.TEST_ENVIRONMENT = True
validate_email = email_validator.validate_email


async def assignable_users():
    from tools.users import Users

    print(await Users.search(q=""))


def ascii_email(v):
    try:
        name = validate_email(v).ascii_email
    except:
        raise PydanticCustomError(
            "name_invalid",
            "The provided name is not a valid local part",
            dict(name_invalid=v),
        )
    return name


def ascii_domain(v):
    try:
        name = validate_email(f"name@{v}").ascii_domain
    except:
        raise PydanticCustomError(
            "name_invalid",
            "The provided name is not a valid domain name",
            dict(name_invalid=v),
        )
    return name


def ascii_local_part(v):
    try:
        name = validate_email(f"{v}@example.org").ascii_local_part
    except:
        raise PydanticCustomError(
            "name_invalid",
            "The provided name is not a valid local part",
            dict(name_invalid=v),
        )
    return name


POLICIES = [
    ("-- None --", "disallow_all"),
    ("Send to external", "send_external"),
    ("Receive from external", "receive_external"),
    ("Send to internal", "send_internal"),
    ("Receive from internal", "receive_internal"),
]

POLICY_DESC = [p[1] for p in POLICIES]


class ObjectDomain(BaseModel):
    @model_validator(mode="after")
    def post_init(self) -> Self:
        if (
            self.dkim_selector == self.arc_selector
            and self.assigned_dkim_keypair != self.assigned_arc_keypair
        ):
            raise PydanticCustomError(
                "selector_conflict",
                "ARC and DKIM selectors cannot be the same while using different keys",
                dict(),
            )
        return self

    @field_validator("bcc_inbound")
    def bcc_inbound_validator(cls, v):
        if v in [None, ""]:
            return ""
        return ascii_email(v)

    @field_validator("bcc_outbound")
    def bcc_outbound_validator(cls, v):
        if v in [None, ""]:
            return ""
        return ascii_email(v)

    @field_validator("domain")
    def domain_validator(cls, v):
        if v in [None, ""]:
            return ""
        return ascii_domain(v)

    domain: str = Field(
        json_schema_extra={
            "title": "Domain name",
            "description": "A unique domain name",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"domain-{str(uuid4())}",
        },
    )

    display_name: str = Field(
        default="",
        json_schema_extra={
            "title": "Display name",
            "description": "The display name of the mailbox",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"mailbox-{str(uuid4())}",
        },
    )

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

    n_mailboxes: conint(ge=0) | Literal[""] = Field(
        default="",
        json_schema_extra={
            "title": "Max. mailboxes",
            "description": "Limit domain to n mailboxes",
            "type": "number",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"n-mailboxes-outbound-{str(uuid4())}",
        },
    )

    ratelimit: conint(ge=0) | Literal[""] = Field(
        default="",
        json_schema_extra={
            "title": "Ratelimit",
            "description": "Amount of elements to allow in a given time unit (see below)",
            "type": "number",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"ratelimit-{str(uuid4())}",
        },
    )

    ratelimit_unit: Literal["day", "hour", "minute"] = Field(
        default="hour",
        json_schema_extra={
            "title": "Policy weight",
            "description": "Policy override options.",
            "type": "select",
            "options": [
                {"name": "Day", "value": "day"},
                {"name": "Hour", "value": "hour"},
                {"name": "Minute", "value": "minute"},
            ],
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"ratelimit-unit-{str(uuid4())}",
        },
    )

    dkim: Annotated[
        Literal[True, False],
        BeforeValidator(lambda x: True if str(x).lower() == "true" else False),
        AfterValidator(lambda x: True if str(x).lower() == "true" else False),
    ] = Field(
        default=True,
        json_schema_extra={
            "title": "DKIM",
            "description": "Enable DKIM signatures",
            "type": "radio",
            "input_extra": 'autocomplete="off"',
            "form_id": f"dkim-signatures-{str(uuid4())}",
        },
    )

    arc: Annotated[
        Literal[True, False],
        BeforeValidator(lambda x: True if str(x).lower() == "true" else False),
        AfterValidator(lambda x: True if str(x).lower() == "true" else False),
    ] = Field(
        default=True,
        json_schema_extra={
            "title": "ARC",
            "description": "Enable ARC signatures",
            "type": "radio",
            "input_extra": 'autocomplete="off"',
            "form_id": f"arc-signatures-{str(uuid4())}",
        },
    )

    dkim_selector: constr(strip_whitespace=True, min_length=1) = Field(
        default="mail",
        json_schema_extra={
            "title": "DKIM Selector",
            "description": "Selector name",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"dkim-selector-{str(uuid4())}",
        },
    )

    arc_selector: constr(strip_whitespace=True, min_length=1) = Field(
        default="mail",
        json_schema_extra={
            "title": "ARC Selector",
            "description": "Selector name",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"arc-selector-{str(uuid4())}",
        },
    )

    assigned_dkim_keypair: str = Field(
        default="",
        json_schema_extra={
            "title": "DKIM key pair",
            "description": "Assign a key pair for DKIM signatures.",
            "type": "keypair",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"assigned-dkim-keypair-{str(uuid4())}",
        },
    )

    assigned_arc_keypair: str = Field(
        default="",
        json_schema_extra={
            "title": "ARC key pair",
            "description": "Assign a key pair for ARC signatures.",
            "type": "keypair",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"assigned-arc-keypair-{str(uuid4())}",
        },
    )

    policies: Annotated[
        Literal[*POLICY_DESC] | list[Literal[*POLICY_DESC]],
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        default=["disallow_all"],
        json_schema_extra={
            "title": "Policies",
            "description": "Policies for this domain.",
            "type": "select:multi",
            "options": [{"name": p[0], "value": p[1]} for p in POLICIES],
            "input_extra": '_="on change if event.target.value is \'disallow_all\' set my selectedIndex to 0 end" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
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

    @property
    def _unique_fields(self):
        return "domain"


class ObjectAddress(BaseModel):
    local_part: constr(strip_whitespace=True, min_length=1) = Field(
        json_schema_extra={
            "title": "Local part",
            "description": "A local part as in <local_part>@example.org; must be unique in combination with its assigned domain",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"local-part-{str(uuid4())}",
        },
    )

    assigned_domain: str = Field(
        json_schema_extra={
            "title": "Assigned domain",
            "description": "Assign a domain for this address.",
            "type": "domain",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"domain-{str(uuid4())}",
        },
    )

    assigned_emailusers: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        default=[],
        json_schema_extra={
            "title": "Assigned email users",
            "description": "Assign this mailbox to email users.",
            "type": "emailusers:multi",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"assigned-emailusers-{str(uuid4())}",
        },
    )

    display_name: str = Field(
        default="%DOMAIN_DISPLAY_NAME%",
        json_schema_extra={
            "title": "Display name",
            "description": "You can use %DOMAIN_DISPLAY_NAME% as variable",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"mailbox-{str(uuid4())}",
        },
    )

    policies: Annotated[
        Literal[*POLICY_DESC] | list[Literal[*POLICY_DESC]],
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        default=["disallow_all"],
        json_schema_extra={
            "title": "Policies",
            "description": "Policies for this address.",
            "type": "select:multi",
            "options": [{"name": p[0], "value": p[1]} for p in POLICIES],
            "input_extra": '_="on change if event.target.value is \'disallow_all\' set my selectedIndex to 0 end" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"policies-{str(uuid4())}",
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

    @property
    def _unique_fields(self):
        return ("local_part", "assigned_domain")


class ObjectUser(BaseModel):
    username: constr(strip_whitespace=True, min_length=1) = Field(
        json_schema_extra={
            "title": "Username",
            "description": "A unique username",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"login-{str(uuid4())}",
        },
    )

    display_name: str = Field(
        default="%MAILBOX_DISPLAY_NAME%",
        json_schema_extra={
            "title": "Display name",
            "description": "You can use %MAILBOX_DISPLAY_NAME% and %DOMAIN_DISPLAY_NAME% variables",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"mailbox-{str(uuid4())}",
        },
    )

    policies: Annotated[
        Literal[*POLICY_DESC] | list[Literal[*POLICY_DESC]],
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        default=["disallow_all"],
        json_schema_extra={
            "title": "Policies",
            "description": "Policies for this address.",
            "type": "select:multi",
            "options": [{"name": p[0], "value": p[1]} for p in POLICIES],
            "input_extra": '_="on change if event.target.value is \'disallow_all\' set my selectedIndex to 0 end" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"policies-{str(uuid4())}",
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

    @property
    def _unique_fields(self):
        return "username"


class ObjectKeyPair(BaseModel):
    name: constr(strip_whitespace=True, min_length=1) = Field(
        default="KeyPair",
        json_schema_extra={
            "title": "Name",
            "description": "A human readable name",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"login-{str(uuid4())}",
        },
    )
    private_key_pem: str
    public_key_base64: str
    key_size: int
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

    @computed_field
    @property
    def dns_formatted(self) -> str:
        return "v=DKIM1; p=" + self.public_key_base64

    @property
    def _unique_fields(self):
        return "name"
