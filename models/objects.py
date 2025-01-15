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
    model_validator,
    field_validator,
    constr,
    ConfigDict,
)
from typing import Annotated, Literal, Any
from uuid import uuid4, UUID
from utils.helpers import ensure_list, to_unique_sorted_str_list
from utils.datetimes import utc_now_as_str


class ObjectBase(BaseModel):
    id: Annotated[str, AfterValidator(lambda v: str(UUID(v)))]
    created: str
    updated: str


class ObjectBaseDomain(ObjectBase):
    details: ObjectDomain

    @computed_field
    @property
    def name(self) -> str:
        return self.details.domain


class ObjectBaseUser(ObjectBase):
    details: ObjectUser

    @computed_field
    @property
    def name(self) -> str:
        return self.details.username


class ObjectBaseAddress(ObjectBase):
    details: ObjectAddress

    @computed_field
    @property
    def name(self) -> str:
        return self.details.local_part


class ObjectBaseKeyPair(ObjectBase):
    details: ObjectKeyPair

    @computed_field
    @property
    def name(self) -> str:
        return self.details.key_name


class ObjectAdd(BaseModel):
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
    details: ObjectDomain


class ObjectAddAddress(ObjectAdd):
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
                2048,
                data["details"].get("assigned_users", []),
                data["details"].get("key_name", "KeyPair"),
            )
        return data

    @classmethod
    def generate_rsa(
        cls, key_size: int = 2048, assigned_users: list = [], key_name: str = "KeyPair"
    ) -> "ObjectKeyPair":
        from utils.dkim import generate_rsa_dkim

        priv, pub = generate_rsa_dkim(key_size)
        return ObjectKeyPair(
            private_key_pem=priv,
            public_key_base64=pub,
            key_size=key_size,
            assigned_users=assigned_users,
            key_name=key_name,
        ).dict()

    details: ObjectKeyPair


class ObjectPatch(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()


class ObjectPatchDomain(ObjectPatch):
    details: ObjectDomain


class ObjectPatchUser(ObjectPatch):
    details: ObjectUser


class ObjectPatchAddress(ObjectPatch):
    details: ObjectAddress


class _ObjectPatchKeyPairHelper(ObjectPatch):
    key_name: constr(strip_whitespace=True, min_length=1) = Field(
        default="KeyPair",
    )
    assigned_users: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ]

    @property
    def _unique_fields(self):
        return "key_name"


class ObjectPatchKeyPair(ObjectPatch):
    details: _ObjectPatchKeyPairHelper


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
