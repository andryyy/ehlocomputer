from pydantic import AfterValidator, BaseModel, Field, validator
from typing import Annotated
from webauthn.helpers.structs import AuthenticatorTransport


class PreTokenRegistration(BaseModel):
    login: Annotated[str, Field(min_length=1)]
    token: str


class TokenRegistration(PreTokenRegistration):
    confirmation_code: Annotated[int, Field(length=6)]


class Registration(BaseModel):
    login: Annotated[str, Field(min_length=1)]


class PreTokenAuthentication(BaseModel):
    login: Annotated[str, Field(min_length=1)]
    token: str


class TokenAuthentication(PreTokenAuthentication):
    confirmation_code: Annotated[int, Field(length=6)]


class Authentication(BaseModel):
    login: Annotated[str, Field(min_length=1)]


class AddCredential(BaseModel):
    """
    Saves bytes id as hex
    """

    id: Annotated[bytes, AfterValidator(lambda x: x.hex())] | str
    friendly_name: str | None
    public_key: Annotated[bytes, AfterValidator(lambda x: x.hex())] | str
    sign_count: int
    transports: list[AuthenticatorTransport] | None = []


class GetCredential(BaseModel):
    """
    Returns hex id as bytes
    """

    id: Annotated[str, AfterValidator(lambda x: bytes.fromhex(x))] | bytes
    friendly_name: str | None
    last_login: str | None = None
    public_key: Annotated[str, AfterValidator(lambda x: bytes.fromhex(x))] | bytes
    sign_count: int
    transports: list[AuthenticatorTransport] | None = []
