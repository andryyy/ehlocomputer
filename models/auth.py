import random

from config.defaults import ACCEPT_LANGUAGES
from pydantic import Field, BaseModel, computed_field, AfterValidator
from typing import Annotated, Literal
from utils.datetimes import ntime_utc_now, utc_now_as_str
from webauthn.helpers.structs import AuthenticatorTransport
from models.forms.users import UserProfile


class TokenConfirmation(BaseModel):
    confirmation_code: Annotated[int, AfterValidator(lambda i: "%06d" % i)]
    token: str = Field(length=14)


class AuthToken(BaseModel):
    login: str = Field(min_length=1)

    @computed_field
    @property
    def token(self) -> str:
        return "%04d-%04d-%04d" % (
            random.randint(0, 9999),
            random.randint(0, 9999),
            random.randint(0, 9999),
        )


class CredentialRead(BaseModel):
    id: Annotated[str, AfterValidator(lambda x: bytes.fromhex(x))] | bytes
    public_key: Annotated[str, AfterValidator(lambda x: bytes.fromhex(x))] | bytes
    friendly_name: str | None
    last_login: str | None = None
    sign_count: int
    transports: list[AuthenticatorTransport] | None = []
    active: bool
    updated: str
    created: str


class CredentialPatch(BaseModel):
    friendly_name: Annotated[str, Field(min_length=1)] | None = None
    active: bool | None = None
    last_login: str | None = None
    sign_count: int | None = None

    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()


class AddCredential(BaseModel):
    id: Annotated[bytes, AfterValidator(lambda x: x.hex())] | str
    public_key: Annotated[bytes, AfterValidator(lambda x: x.hex())] | str
    sign_count: int
    friendly_name: str = "New passkey"
    transports: list[AuthenticatorTransport] | None = []
    active: bool = True

    @computed_field
    @property
    def created(self) -> str:
        return utc_now_as_str()

    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()


class UserSession(BaseModel):
    id: str
    login: str
    acl: list | str
    cred_id: str | None = None
    lang: Literal[*ACCEPT_LANGUAGES] = "en"
    profile: dict | UserProfile | None = {}
    login_ts: float = Field(default_factory=ntime_utc_now)
