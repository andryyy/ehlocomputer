from config.defaults import USER_ACLS
from models.auth import CredentialRead
from models.forms.users import UserProfile
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    computed_field,
    model_validator,
    field_validator,
)
from pydantic_core import PydanticCustomError
from utils.datetimes import utc_now_as_str
from utils.helpers import ensure_list, to_unique_sorted_str_list
from typing import Annotated, Literal
from uuid import UUID, uuid4


class _Users_attr(BaseModel):
    login: Annotated[
        str | list[str] | None,
        AfterValidator(lambda v: ensure_list(v) or None),
    ] = None
    id: Annotated[
        str | list[str] | None,
        AfterValidator(lambda v: ensure_list(v) or None),
    ] = None

    @model_validator(mode="after")
    def post_init(self):
        if (self.id and self.login) or not (self.id or self.login):
            raise PydanticCustomError(
                "attr",
                "Either login or id must be defined",
                dict(provided_attr=None),
            )
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
        if isinstance(self.login, list) and len(self.login) == 1:
            self.login = self.login.pop()

        return self

    @computed_field
    @property
    def matched_attr(self) -> str:
        if self.id:
            return "id"
        if self.login:
            return "login"
        return None


class User(BaseModel):
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
