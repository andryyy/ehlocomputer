import uuid

from . import utc_now_as_str
from pydantic import AfterValidator, BaseModel, Field
from typing import Annotated
from typing_extensions import NotRequired, TypedDict


class Configuration(TypedDict):
    raw_config: NotRequired[dict]
    revision: NotRequired[str]


class ConfigCreate(BaseModel):
    id: Annotated[str, Field(default_factory=lambda: str(uuid.uuid4()))]
    name: Annotated[str, Field(min_length=1)]
    configuration: dict = {}
    historic: list = []
    created: Annotated[str, Field(default_factory=utc_now_as_str)]
    updated: Annotated[str, Field(default_factory=utc_now_as_str)]


class ConfigPatch(BaseModel):
    id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))]
    name: Annotated[str, Field(min_length=1)]
    updated: Annotated[str, Field(default_factory=utc_now_as_str)]
    configuration: Configuration
    historic: list = []
