import random
from config.defaults import USER_ACLS, ACCESS_TOKEN_FORMAT, ACCEPT_LANGUAGES
from pydantic import (
    AfterValidator,
    BeforeValidator,
    BaseModel,
    Field,
    field_validator,
    computed_field,
    ConfigDict,
    constr,
    TypeAdapter,
    ValidationError,
)
from pydantic_core import PydanticCustomError
from utils.datetimes import utc_now_as_str
from utils.helpers import ensure_list, to_unique_sorted_str_list
from typing import Annotated, Literal
from uuid import UUID, uuid4
from email_validator import validate_email
from utils.datetimes import ntime_utc_now, utc_now_as_str
from webauthn.helpers.structs import AuthenticatorTransport


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
    friendly_name: str
    last_login: str
    sign_count: int
    transports: list[AuthenticatorTransport] | None = []
    active: bool
    updated: str
    created: str


class CredentialPatch(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    friendly_name: constr(strip_whitespace=True, min_length=1)
    active: bool
    last_login: str
    sign_count: int

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
    last_login: str = ""

    @computed_field
    @property
    def created(self) -> str:
        return utc_now_as_str()

    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()


class UserProfile(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    @field_validator("email", mode="before")
    def email_validator(cls, v):
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

    @field_validator("access_tokens", mode="after")
    def access_tokens_validator(cls, v):
        for s in v:
            try:
                TypeAdapter(ACCESS_TOKEN_FORMAT).validate_python(s)
            except ValidationError as e:
                s_priv = s[:3] + (s[3:] and "***")
                raise PydanticCustomError(
                    "access_tokens",
                    f"The provided token {s_priv} is invalid",
                    dict(access_token=s, list_index=v.index(s)),
                )

        return v

    email: str = Field(
        default="",
        json_schema_extra={
            "title": "Email address",
            "description": "Your email address is optional",
            "type": "email",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"email-{str(uuid4())}",
        },
    )

    access_tokens: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = Field(
        default=[],
        json_schema_extra={
            "title": "Access tokens",
            "description": "Tokens to access the API. Save profile after removing a token.",
            "type": "list:text",
            "input_extra": 'autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"',
            "form_id": f"access-tokens-{str(uuid4())}",
        },
    )

    permit_auth_requests: Annotated[
        Literal[True, False],
        BeforeValidator(lambda x: True if str(x).lower() == "true" else False),
        AfterValidator(lambda x: True if str(x).lower() == "true" else False),
    ] = Field(
        default=True,
        json_schema_extra={
            "title": "Authentication requests",
            "description": "Allow other devices to issue authentication requests to active sessions via pop-up",
            "type": "radio",
            "input_extra": 'autocomplete="off"',
            "form_id": f"proxy-login-{str(uuid4())}",
        },
    )


class User(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    id: Annotated[str, AfterValidator(lambda v: str(UUID(v)))]
    login: str
    credentials: dict[str, CredentialRead] | list[str] = {}
    acl: list[Literal[*USER_ACLS]]
    groups: list[constr(strip_whitespace=True, min_length=1)] = []
    profile: UserProfile
    created: str
    updated: str


class UserGroups(BaseModel):
    name: constr(strip_whitespace=True, min_length=1)
    new_name: constr(strip_whitespace=True, min_length=1)
    members: Annotated[
        str | list,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = []


class UserAdd(BaseModel):
    login: str = constr(strip_whitespace=True, min_length=1)
    credentials: list[str] = []
    acl: list[Literal[*USER_ACLS]] = ["user"]
    profile: UserProfile = UserProfile.parse_obj({})
    groups: list[constr(strip_whitespace=True, min_length=1)] = []

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
    groups: Annotated[
        constr(strip_whitespace=True, min_length=1)
        | list[constr(strip_whitespace=True, min_length=1)],
        AfterValidator(lambda v: ensure_list(v)),
    ] = []

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
