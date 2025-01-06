import asyncio
import models.auth as auth_model
import models.users as users_model
import re

from config import defaults
from config.database import *
from config.logs import logger
from pydantic import Field, constr, validate_call
from tools import cluster_task, evaluate_db_params
from utils.helpers import ensure_list, merge_deep
from uuid import UUID


def _create_credentials_mapping(credentials: dict):
    user_credentials = dict()
    for c in credentials:
        user_credentials.update({c["id"]: auth_model.CredentialRead.parse_obj(c)})
    return user_credentials


@validate_call
async def create(data: dict):
    db_params = evaluate_db_params()
    create_user = users_model.UserAdd.parse_obj(data)

    async with TinyDB(**db_params) as db:
        if db.table("users").search(Query().login == create_user.login):
            raise ValueError("name", "The provided login name exists")
        insert_data = create_user.dict()
        db.table("users").insert(insert_data)

    return insert_data["id"]


@validate_call
async def what_id(login: str):
    db_params = evaluate_db_params()

    async with TinyDB(**db_params) as db:
        user = db.table("users").get(Query().login == login)

    if user:
        return user["id"]
    else:
        raise ValueError("login", "The provided login name is unknown")


@validate_call
async def get(user_id: UUID):
    db_params = evaluate_db_params()

    async with TinyDB(**db_params) as db:
        user = users_model.User.parse_obj(
            db.table("users").get(Query().id == str(user_id))
        )
        credentials = db.table("credentials").search(
            (Query().id.one_of(user.credentials))
        )
        user.credentials = _create_credentials_mapping(credentials)
        return user


@validate_call
async def delete(user_id: UUID):
    db_params = evaluate_db_params()

    async with TinyDB(**db_params) as db:
        user = db.table("users").get(Query().id == str(user_id))
        for credential_hex_id in user["credentials"]:
            db.table("credentials").remove(Query().id == credential_hex_id)
        deleted = db.table("users").remove(Query().id == str(user_id))
        return user["id"]


@validate_call
async def create_credential(user_id: UUID, data: dict):
    db_params = evaluate_db_params()

    credential = auth_model.AddCredential.parse_obj(data)
    async with TinyDB(**db_params) as db:
        user = db.table("users").get(Query().id == str(user_id))
        db.table("credentials").insert(credential.dict())
        user["credentials"].append(credential.id)
        db.table("users").update(
            {"credentials": user["credentials"]},
            Query().id == str(user_id),
        )
        return credential.id


@validate_call
async def delete_credential(
    user_id: UUID, hex_id: constr(pattern=r"^[0-9a-fA-F]+$", min_length=2)
):
    db_params = evaluate_db_params()

    async with TinyDB(**db_params) as db:
        user = db.table("users").get(Query().id == str(user_id))
        if hex_id in user["credentials"]:
            user["credentials"].remove(hex_id)
            db.table("credentials").remove(Query().id == hex_id)
            db.table("users").update(
                {"credentials": user["credentials"]}, Query().id == str(user_id)
            )
            return hex_id


@validate_call
async def patch(user_id: UUID, data: dict):
    db_params = evaluate_db_params()
    patch_user = users_model.UserPatch.parse_obj(data)

    async with TinyDB(**db_params) as db:
        if db.table("users").get(
            (Query().login == patch_user.login) & (Query().id != str(user_id))
        ):
            raise ValueError("login", "The provided login name exists")

        user = db.table("users").get(Query().id == str(user_id))

        orphaned_credentials = [
            c for c in user["credentials"] if c not in patch_user.credentials
        ]

        db.table("users").update(
            validated_data.dict(exclude_none=True),
            Query().id == str(user_id),
        )
        db.table("credentials").remove(Query().id.one_of(orphaned_credentials))

        return user["id"]


@validate_call
async def patch_profile(user_id: UUID, data: dict):
    db_params = evaluate_db_params()

    async with TinyDB(**db_params) as db:
        user = db.table("users").get(Query().id == str(user_id))
        if not user:
            raise ValueError("name", "The provided user does not exist")

        patched_user_profile = users_model.UserProfile.model_validate(
            merge_deep(user["profile"], data)
        )

        db.table("users").update(
            {"profile": patched_user_profile.dict()},
            Query().id == str(user_id),
        )

        return user_id


@validate_call
async def patch_credential(
    user_id: UUID, hex_id: constr(pattern=r"^[0-9a-fA-F]+$", min_length=2), data: dict
):
    db_params = evaluate_db_params()

    user = await get(user_id=user_id)
    if hex_id not in user.credentials:
        raise ValueError(
            "hex_id",
            "The provided credential ID was not found in user context",
        )

    async with TinyDB(**db_params) as db:
        patched_credential = auth_model.CredentialPatch.model_validate(
            merge_deep(user.credentials[hex_id].dict(), data)
        )
        db.table("credentials").update(patched_credential.dict(), Query().id == hex_id)
        return hex_id


@validate_call
async def search(self, name: constr(strip_whitespace=True, min_length=0) = Field(...)):
    db_params = evaluate_db_params()

    def search_name(s):
        return name in s

    async with TinyDB(**db_params) as db:
        matches = db.table("users").search(Query().login.test(search_name))
        _parsed = []
        for user in matches:
            user = users_model.User.parse_obj(user)
            credentials = db.table("credentials").search(
                Query().id.one_of(user.credentials)
            )
            user.credentials = _create_credentials_mapping(credentials)
            _parsed.append(user)

    return _parsed


@validate_call
async def search_credential(
    self, q: constr(strip_whitespace=True, min_length=0) = Field(...)
):
    db_params = evaluate_db_params()

    in_q = lambda s: q in s
    async with TinyDB(**db_params) as db:
        matches = db.table("credentials").search(
            (Query().id.test(in_q)) | (Query().friendly_name.test(in_q))
        )
        return _create_credentials_mapping(matches)
