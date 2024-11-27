from models.forms.objects import (
    ObjectPatchContactForm,
    ObjectPatchCalendarForm,
    ObjectPatchAppointmentForm,
)
from pydantic_core import PydanticCustomError
from pydantic import (
    Field,
    BaseModel,
    computed_field,
    AfterValidator,
    constr,
    model_validator,
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


class ObjectBaseCalendar(ObjectBase):
    details: ObjectPatchCalendarForm = {}


class ObjectBaseContact(ObjectBase):
    details: ObjectPatchContactForm = {}


class ObjectBaseAppointment(ObjectBase):
    details: ObjectPatchAppointmentForm = {}


class ObjectAdd(BaseModel):
    name: constr(strip_whitespace=True, min_length=1) = Field(...)
    details: dict = {}

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


class ObjectDelete(BaseModel):
    id: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ]


class ObjectPatch(BaseModel):
    name: Annotated[constr(strip_whitespace=True), Field(min_length=1)]

    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()


class ObjectPatchContact(ObjectPatch):
    details: ObjectPatchContactForm


class ObjectPatchCalendar(ObjectPatch):
    details: ObjectPatchCalendarForm


class ObjectPatchAppointment(ObjectPatch):
    details: ObjectPatchAppointmentForm


model_classes = {
    "types": ["contacts", "calendars", "appointments"],
    "forms": {
        "contacts": ObjectPatchContactForm,
        "calendars": ObjectPatchCalendarForm,
        "appointments": ObjectPatchAppointmentForm,
    },
    "patch": {
        "contacts": ObjectPatchContact,
        "calendars": ObjectPatchCalendar,
        "appointments": ObjectPatchAppointment,
    },
    "base": {
        "contacts": ObjectBaseContact,
        "calendars": ObjectBaseCalendar,
        "appointments": ObjectBaseAppointment,
    },
}


class _Objects_attr(BaseModel):
    id: Annotated[
        str | list[str] | None,
        AfterValidator(lambda v: ensure_list(v) or None),
    ] = None
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
