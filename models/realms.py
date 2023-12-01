import os
import uuid

from . import ensure_list, get_validated_fqdn, to_unique_sorted_str_list, utc_now_as_str
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic.networks import IPvAnyAddress
from typing import Annotated
from typing_extensions import TypedDict


class RealmCreate(BaseModel):
    id: Annotated[str, Field(default_factory=lambda: str(uuid.uuid4()))]
    bootstrapped: bool = Field(False, frozen=True)
    name: Annotated[str, Field(min_length=1)]
    default: bool = False
    neighbours: list = []
    podman_socket: str = "/tmp/ehlopodman.sock"
    #origin: str = Field("ehlo.localdomain", frozen=True)
    created: Annotated[str, Field(default_factory=utc_now_as_str)]
    updated: Annotated[str, Field(default_factory=utc_now_as_str)]


class RealmPatch(BaseModel):
    id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))]
    origin: Annotated[str, Field(min_length=3)]
    bootstrapped: bool = Field(True, frozen=True)
    name: Annotated[str, Field(min_length=1)]
    default: bool | None = None
    updated: Annotated[str, Field(default_factory=utc_now_as_str)]
    neighbours: list = []
    podman_socket: str = "/tmp/ehlopodman.sock"

    @field_validator("neighbours")
    @classmethod
    def check_neighbours(cls, neighbours: list, info: ValidationInfo):
        _addresses = []
        _neighbours = []
        for neighbour in neighbours:
            try:
                IPvAnyAddress(neighbour["address"])
            except:
                raise ValueError(f"{neighbour['address']} is not a valid IP address")

            assert (
                neighbour["address"] not in _addresses
            ), f"{neighbour['address']} is a duplicate"

            assert get_validated_fqdn(neighbour["hostname"])

            _neighbours.append(neighbour)
            _addresses.append(neighbour["address"])

        return _neighbours
