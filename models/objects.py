import email_validator
import json
from models.forms.objects import (
    ObjectDomain,
    ObjectAddress,
    ObjectUser,
    ObjectKeyPair,
)
from pydantic_core import PydanticCustomError
from pydantic import (
    Field,
    BaseModel,
    computed_field,
    AfterValidator,
    constr,
    model_validator,
    field_validator,
    ConfigDict,
)
from typing import Annotated, Literal, Any
from uuid import uuid4, UUID
from utils.helpers import ensure_list, to_unique_sorted_str_list
from utils.datetimes import utc_now_as_str

email_validator.TEST_ENVIRONMENT = True
validate_email = email_validator.validate_email


class ObjectBase(BaseModel):
    id: str
    name: constr(strip_whitespace=True, min_length=1) = Field(...)
    created: str
    updated: str


class ObjectBaseDomain(ObjectBase):
    name: constr(strip_whitespace=True, min_length=1) = Field(
        default="",
        json_schema_extra={
            "title": "Domain name",
            "description": "A valid domain name.",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"name-{str(uuid4())}",
        },
    )

    details: ObjectDomain


class ObjectBaseUser(ObjectBase):
    name: constr(strip_whitespace=True, min_length=1) = Field(
        default="",
        json_schema_extra={
            "title": "Mail user",
            "description": "A username to identify to a server.",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"name-{str(uuid4())}",
        },
    )
    details: ObjectUser


class ObjectBaseAddress(ObjectBase):
    name: constr(strip_whitespace=True, min_length=1) = Field(
        default="",
        json_schema_extra={
            "title": "Email address",
            "description": "Must be a valid email address.",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"name-{str(uuid4())}",
        },
    )

    assigned_domain: str = Field(
        default="",
        json_schema_extra={
            "title": "Assigned domain",
            "description": "Assign a domain for this address.",
            "type": "domain",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"domain-{str(uuid4())}",
        },
    )

    details: ObjectAddress


class ObjectBaseKeyPair(ObjectBase):
    name: constr(strip_whitespace=True, min_length=1) = Field(
        default="",
        json_schema_extra={
            "title": "Display name",
            "description": "A display name for a key pair.",
            "type": "text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"name-{str(uuid4())}",
        },
    )
    details: ObjectKeyPair


class ObjectAdd(BaseModel):
    name: constr(strip_whitespace=True, min_length=1) = Field(...)

    @computed_field
    @property
    def id(self) -> str:
        return str(uuid4())

    @computed_field
    @property
    def created(self) -> str:
        return utc_now_as_str()

    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()


class ObjectAddDomain(ObjectAdd):
    @field_validator("name", mode="before")
    def name_as_domain(cls, v):
        try:
            name = validate_email(f"name@{v}").ascii_domain
        except:
            raise PydanticCustomError(
                "name_invalid",
                "The provided name is not a valid domain name",
                dict(name_invalid=v),
            )
        return name

    details: ObjectDomain


class ObjectAddAddress(ObjectAdd):
    @field_validator("name", mode="before")
    def email_validator(cls, v):
        try:
            name = validate_email(f"{v}@example.org").ascii_local_part
        except:
            raise PydanticCustomError(
                "name_invalid",
                "The provided name is not a valid email address",
                dict(name_invalid=v),
            )
        return name

    assigned_domain: str
    details: ObjectAddress


class ObjectAddUser(ObjectAdd):
    details: ObjectUser


class ObjectAddKeyPair(ObjectAdd):
    @model_validator(mode="before")
    @classmethod
    def pre_init(cls, data: Any) -> Any:
        if not all(
            data["details"].get(k)
            for k in ObjectKeyPair.__fields__
            if k != "assigned_users"
        ):
            data["details"] = cls.generate_rsa(
                2048, data["details"].get("assigned_users", [])
            )
        return data

    @classmethod
    def generate_rsa(
        cls, key_size: int = 2048, assigned_users: list = []
    ) -> "ObjectKeyPair":
        from utils.dkim import generate_rsa_dkim

        priv, pub = generate_rsa_dkim(key_size)
        return ObjectKeyPair(
            private_key_pem=priv,
            public_key_base64=pub,
            key_size=key_size,
            assigned_users=assigned_users,
        ).dict()

    details: ObjectKeyPair


class ObjectPatch(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    name: Annotated[constr(strip_whitespace=True), Field(min_length=1)]

    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()


class ObjectPatchDomain(ObjectPatch):
    @field_validator("name", mode="before")
    def name_as_domain(cls, v):
        try:
            name = validate_email(f"name@{v}").ascii_domain
        except:
            raise PydanticCustomError(
                "name_invalid",
                "The provided name is not a valid domain name",
                dict(name_invalid=v),
            )
        return name

    details: ObjectDomain


class ObjectPatchUser(ObjectPatch):
    details: ObjectUser


class ObjectPatchAddress(ObjectPatch):
    @field_validator("name", mode="before")
    def email_validator(cls, v):
        try:
            name = validate_email(f"{v}@example.org").ascii_local_part
        except:
            raise PydanticCustomError(
                "name_invalid",
                "The provided name is not a valid email address",
                dict(name_invalid=v),
            )
        return name

    assigned_domain: str
    details: ObjectAddress


class ObjectPatchKeyPair(ObjectPatch):
    details: ObjectKeyPair


model_classes = {
    "types": ["domains", "addresses", "emailusers", "keypairs"],
    "forms": {
        "domains": ObjectDomain,
        "addresses": ObjectAddress,
        "emailusers": ObjectUser,
        "keypairs": ObjectKeyPair,
    },
    "patch": {
        "domains": ObjectPatchDomain,
        "addresses": ObjectPatchAddress,
        "emailusers": ObjectPatchUser,
        "keypairs": ObjectPatchKeyPair,
    },
    "add": {
        "domains": ObjectAddDomain,
        "addresses": ObjectAddAddress,
        "emailusers": ObjectAddUser,
        "keypairs": ObjectAddKeyPair,
    },
    "base": {
        "domains": ObjectBaseDomain,
        "addresses": ObjectBaseAddress,
        "emailusers": ObjectBaseUser,
        "keypairs": ObjectBaseKeyPair,
    },
}


class ObjectIdList(BaseModel):
    object_id: Annotated[
        UUID | list[UUID],
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ]
