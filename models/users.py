import uuid

from pydantic import AfterValidator, BaseModel, Field
from typing import Annotated


class AddUser(BaseModel):
    id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))]
    login: Annotated[str, Field(min_length=1)]
    credentials: list[Annotated[bytes, AfterValidator(lambda x: x.hex())] | str] = []
