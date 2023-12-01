import os
import uuid
import json

from models import realms as realms_model
from pydantic import validate_arguments, Field, AfterValidator
from typing import Annotated
from config.database import TinyDB, Query


@validate_arguments
def validate_realm_database(
    id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))]
):
    if id not in [f for f in os.listdir("realms/databases") if not f.endswith(".json")]:
        raise FileNotFoundError(f"Realm database file does not exist")

    with open(f"realms/databases/{id}", "r") as json_file:
        try:
            data = json.load(json_file)
        except Exception as e:
            raise ValueError("Realm file exists but cannot be read as JSON")

    return True


@validate_arguments
def get_realm_by_id(
    realm_id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))]
):
    with TinyDB("realms/realms.json") as db:
        realms_table = db.table("realms")
        match = realms_table.get(Query().id == realm_id)
        if match:
            assert validate_realm_database(match["id"])
        return match


@validate_arguments
def get_realm_by_name(name: Annotated[str, Field(min_length=1)]):
    with TinyDB("realms/realms.json") as db:
        realms_table = db.table("realms")
        match = realms_table.get(Query().name == name)
        if match:
            assert validate_realm_database(match["id"])
        return match
