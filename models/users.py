from config.defaults import USER_ACLS
from models.auth import CredentialRead
from models.forms.users import UserProfile
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    computed_field,
    ConfigDict,
)
from pydantic_core import PydanticCustomError
from utils.datetimes import utc_now_as_str
from utils.helpers import ensure_list, to_unique_sorted_str_list
from typing import Annotated, Literal
from uuid import UUID, uuid4


class User(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    id: Annotated[str, AfterValidator(lambda v: str(UUID(v)))]
    login: str
    credentials: dict[str, CredentialRead] | list[str] = {}
    acl: list[Literal[*USER_ACLS]]
    profile: UserProfile
    created: str
    updated: str


class UserAdd(BaseModel):
    login: str = Field(min_length=1)
    credentials: list[str] = []
    acl: list[Literal[*USER_ACLS]] = ["user"]
    profile: UserProfile = UserProfile.parse_obj({})

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


class UserPatch(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    login: str = Field(min_length=1)
    acl: Annotated[
        Literal[*USER_ACLS] | list[Literal[*USER_ACLS]],
        AfterValidator(lambda v: ensure_list(v)),
    ] = []
    credentials: Annotated[
        str | list[str],
        AfterValidator(lambda v: ensure_list(v)),
    ] = []

    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()
