import re
import uuid

from . import ensure_list, to_unique_sorted_str_list, utc_now_as_str
from email_validator import validate_email
from pydantic import AfterValidator, BaseModel, Field, validator
from pydantic_core import PydanticCustomError
from typing import Annotated, Literal


class ObjectSearch(BaseModel):
    q: str


class ObjectBase(BaseModel):
    id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))]
    name: Annotated[str, Field(min_length=1)]
    created: Annotated[str, Field(default_factory=utc_now_as_str)]
    updated: Annotated[str, Field(default_factory=utc_now_as_str)]


class ObjectCreateSetting(ObjectBase):
    settings_rule: int = 0
    pass


class ObjectCreateDomain(ObjectBase):
    @validator("name", pre=True)
    def domain_check(cls, v):
        try:
            if re.findall("%.+%", v):
                raise Exception()
            domain_part = validate_email(
                f"validator@{v}", check_deliverability=False
            ).ascii_domain
        except:
            raise PydanticCustomError(
                "name_invalid",
                "The provided domain name is invalid",
                dict(provided_name=v),
            )
        return domain_part

    name: str


class ObjectCreateRecipient(ObjectBase):
    @validator("name", pre=True)
    def name_check(cls, v):
        try:
            if re.findall("%.+%", v):
                raise Exception()
            local_part = validate_email(
                f"{v}@example.com", check_deliverability=False
            ).ascii_local_part
        except:
            raise PydanticCustomError(
                "name_invalid",
                "The provided recipient name is invalid",
                dict(provided_name=v),
            )
        return local_part

    name: str


class ObjectDelete(BaseModel):
    id: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ]
    updated: Annotated[str, Field(default_factory=utc_now_as_str)]


class ObjectPatchRecipients(BaseModel):
    id: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ]
    name: Annotated[
        str,
        AfterValidator(
            lambda x: validate_email(
                f"{x}@example.com", check_deliverability=False
            ).ascii_local_part
        ),
    ] | None
    updated: Annotated[str, Field(default_factory=utc_now_as_str)]


class ObjectPatchDomains(BaseModel):
    id: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ]
    name: Annotated[
        str,
        AfterValidator(
            lambda x: validate_email(
                f"validator@{x}", check_deliverability=False
            ).ascii_domain
        ),
    ] | None
    updated: Annotated[str, Field(default_factory=utc_now_as_str)]


# http, ldap, and static will be validated in a dynamic model
class ObjectPatchSettings(BaseModel):
    id: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ]
    name: Annotated[str, Field(min_length=1)]
    settings_rule: int
    source: Literal["ldap", "http", "static"] | None = None

    http_request_body: str | None = ""
    http_request_header: str | None = ""
    http_response: dict | None = {}
    http_status_code: int | str | None = ""
    http_url: str | None = ""

    ldap_attribute: str | None = ""
    ldap_uri: str | None = ""
    ldap_base_dn: str | None = ""
    ldap_bind_dn: str | None = ""
    ldap_bind_passwd: str | None = None
    ldap_search_scope: Literal[
        "SCOPE_BASE", "SCOPE_ONELEVEL", "SCOPE_SUBTREE"
    ] | None = None
    ldap_filter: str | None = ""

    static_boolean: bool | str | None = ""
    static_number: int | str | None = ""
    static_text: str | None = ""

    updated: Annotated[str, Field(default_factory=utc_now_as_str)]
