from models.forms.objects import (
    ObjectMailbox,
    ObjectDomain,
    ObjectGroup,
)
from pydantic_core import PydanticCustomError
from pydantic import (
    Field,
    BaseModel,
    computed_field,
    AfterValidator,
    constr,
    model_validator,
    ConfigDict,
)
from typing import Annotated, Literal
from uuid import uuid4, UUID
from utils.helpers import ensure_list, to_unique_sorted_str_list
from utils.datetimes import utc_now_as_str


class ObjectBase(BaseModel):
    id: str
    name: constr(strip_whitespace=True, min_length=1) = Field(...)
    created: str
    updated: str


class ObjectBaseDomain(ObjectBase):
    details: ObjectDomain = {}


class ObjectBaseMailbox(ObjectBase):
    details: ObjectMailbox = {}


class ObjectBaseGroup(ObjectBase):
    details: ObjectGroup = {}


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
    details: ObjectDomain


class ObjectAddMailbox(ObjectAdd):
    details: ObjectMailbox


class ObjectAddGroup(ObjectAdd):
    details: ObjectGroup


class ObjectDelete(BaseModel):
    id: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ]


class ObjectPatch(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    name: Annotated[constr(strip_whitespace=True), Field(min_length=1)]

    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()


class ObjectPatchDomain(ObjectPatch):
    details: ObjectDomain


class ObjectPatchMailbox(ObjectPatch):
    details: ObjectMailbox


class ObjectPatchGroup(ObjectPatch):
    details: ObjectGroup


model_classes = {
    "types": ["domains", "mailboxes", "groups"],
    "forms": {
        "domains": ObjectDomain,
        "mailboxes": ObjectMailbox,
        "groups": ObjectGroup,
    },
    "patch": {
        "domains": ObjectPatchDomain,
        "mailboxes": ObjectPatchMailbox,
        "groups": ObjectPatchGroup,
    },
    "add": {
        "domains": ObjectAddDomain,
        "mailboxes": ObjectAddMailbox,
        "groups": ObjectAddGroup,
    },
    "base": {
        "domains": ObjectBaseDomain,
        "mailboxes": ObjectBaseMailbox,
        "groups": ObjectBaseGroup,
    },
}


class _Objects_attr(BaseModel):
    id: Annotated[
        str | list[str],
        AfterValidator(lambda v: ensure_list(v) or None),
    ]
    object_type: Literal[*model_classes["types"]]

    @model_validator(mode="after")
    def post_init(self):
        try:
            if isinstance(self.id, list):
                if len(self.id) == 1:
                    self.id = str(UUID(self.id.pop()))
                else:
                    self.id = [str(UUID(uid)) for uid in self.id]
            elif isinstance(self.id, str):
                self.id = str(UUID(self.id))
        except:
            raise PydanticCustomError(
                "id",
                "One or more IDs cannot be intepreted as UUID values",
                dict(provided_id=self.id),
            )
        return self
