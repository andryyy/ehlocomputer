import uuid

from config import defaults
from config.database import *
from pydantic import AfterValidator, validate_arguments
from typing import Annotated


@validate_arguments
def get_user_by_login(login: str, realm_path: str):
    with TinyDB(**defaults.TINYDB, path=realm_path) as db:
        users_table = db.table("users")
        return users_table.get(Query().login == login)


@validate_arguments
def get_user_by_id(
    user_id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))],
    realm_path: str,
):
    with TinyDB(**defaults.TINYDB, path=realm_path) as db:
        users_table = db.table("users")
        return users_table.get(Query().id == user_id)


@validate_arguments
def get_user_credentials_by_login(login: str, realm_path: str):
    user = get_user_by_login(login=login, realm_path=realm_path)
    if user:
        with TinyDB(**defaults.TINYDB, path=realm_path) as db:
            return db.table("credentials").search(
                Query().id.one_of(user["credentials"])
            )
