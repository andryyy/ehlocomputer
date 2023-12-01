import uuid

from config import defaults
from config import logger
from pydantic import AfterValidator
from pydantic import validate_arguments
from tinydb import Query, TinyDB
from typing import Annotated, Any, Literal


@validate_arguments
def get_object_by_id(
    object_type: Literal["domains", "recipients", "settings"],
    object_id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))],
    realm_path: str,
):
    with TinyDB(**defaults.TINYDB, path=realm_path) as db:
        object_table = db.table(object_type)
        return object_table.get(Query().id == object_id)


@validate_arguments
def get_object_by_name(
    object_type: Literal["domains", "recipients", "settings"],
    name: str,
    realm_path: str,
):
    with TinyDB(**defaults.TINYDB, path=realm_path) as db:
        object_table = db.table(object_type)
        return object_table.get(Query().name == name)
