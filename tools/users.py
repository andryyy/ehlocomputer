import asyncio
import models.auth as auth_model
import models.users as users_model
import re

from config import defaults
from config.database import *
from config.logs import logger
from pydantic import Field, constr, validate_call
from tools import cluster_task, evaluate_db_params
from utils.helpers import ensure_list
from uuid import UUID


def _create_credentials_mapping(credentials: dict):
    user_credentials = dict()
    for c in credentials:
        user_credentials.update({c["id"]: auth_model.CredentialRead.parse_obj(c)})
    return user_credentials


class Users:
    def __init__(self):
        self.db_params = evaluate_db_params()

    class create:
        def __init__(self, *args, **kwargs):
            self.db_params = evaluate_db_params()

            for key, value in kwargs.items():
                setattr(self, key, value)

        @cluster_task("users_create_user", enforce_uuid=True)
        async def user(self, data: dict):
            validated_data = users_model.UserAdd.parse_obj(data).dict()

            if self.uuid:
                validated_data["id"] = self.uuid

            async with TinyDB(**self.db_params) as db:
                name_conflict = db.table("users").search(
                    Query().login == validated_data["login"]
                )
                if name_conflict:
                    raise ValueError("name", "The provided login name exists")
                db.table("users").insert(validated_data)

            return validated_data["id"]

    class user:
        def __init__(self, *args, **kwargs):
            self.db_params = evaluate_db_params()

            for key, value in kwargs.items():
                setattr(self, key, value)

            users_attr = users_model._Users_attr.parse_obj(kwargs)

            # Base attributes
            self.id = users_attr.id
            self.login = users_attr.login

            self._matched_attr = users_attr.matched_attr
            self._query_filter = getattr(Query(), users_attr.matched_attr) == getattr(
                self, users_attr.matched_attr
            )

        async def get(self) -> None:
            async with TinyDB(**self.db_params) as db:
                user = users_model.User.parse_obj(
                    db.table("users").get(self._query_filter)
                )
                credentials = db.table("credentials").search(
                    (Query().id.one_of(user.credentials))
                )
                user.credentials = _create_credentials_mapping(credentials)
                return user

        @cluster_task("users_user_delete")
        async def delete(self):
            async with TinyDB(**self.db_params) as db:
                user = db.table("users").get(self._query_filter)
                for credential_hex_id in user["credentials"]:
                    db.table("credentials").remove(Query().id == credential_hex_id)
                deleted = db.table("users").remove(self._query_filter)
                return user["id"]

        @cluster_task("users_user_create_credential")
        async def create_credential(self, data: dict):
            validated_data = auth_model.AddCredential.parse_obj(data).dict()
            async with TinyDB(**self.db_params) as db:
                user = db.table("users").get(self._query_filter)
                db.table("credentials").insert(validated_data)
                user["credentials"].append(validated_data["id"])
                db.table("users").update(
                    {"credentials": user["credentials"]},
                    self._query_filter,
                )
                return validated_data["id"]

        @cluster_task("users_user_delete_credential")
        @validate_call
        async def delete_credential(
            self, hex_id: constr(pattern=r"^[0-9a-fA-F]+$", min_length=2)
        ):
            async with TinyDB(**self.db_params) as db:
                user = db.table("users").get(self._query_filter)
                if hex_id in user["credentials"]:
                    user["credentials"].remove(hex_id)
                    db.table("credentials").remove(Query().id == hex_id)
                    db.table("users").update(
                        {"credentials": user["credentials"]},
                        self._query_filter,
                    )
                    return hex_id

        @cluster_task("users_user_patch")
        async def patch(self, data: dict):
            validated_data = users_model.UserPatch.parse_obj(data)
            async with TinyDB(**self.db_params) as db:
                name_conflict = db.table("users").search(
                    (Query().login == validated_data.login) & (~(self._query_filter))
                )
                if name_conflict:
                    raise ValueError("login", "The provided login name exists")

                user = db.table("users").get(self._query_filter)
                orphaned_credentials = [
                    c
                    for c in user["credentials"]
                    if c not in validated_data.credentials
                ]
                db.table("users").update(
                    validated_data.dict(exclude_none=True),
                    self._query_filter,
                )
                db.table("credentials").remove(Query().id.one_of(orphaned_credentials))
                return user["id"]

        @cluster_task("users_user_patch_profile")
        async def patch_profile(self, data: dict):
            validated_data = users_model.UserProfile.parse_obj(data).dict(
                exclude_none=True
            )
            async with TinyDB(**self.db_params) as db:
                user = db.table("users").get(self._query_filter)
                if not user:
                    raise ValueError("name", "The provided user does not exist")
                patched = db.table("users").update(
                    {"profile": user["profile"] | validated_data},
                    self._query_filter,
                )
                return user["id"]

        @cluster_task("users_user_patch_credential")
        async def patch_credential(
            self,
            hex_id: constr(pattern=r"^[0-9a-fA-F]+$", min_length=2),
            data: dict,
        ):
            validated_data = auth_model.CredentialPatch.parse_obj(data)
            async with TinyDB(**self.db_params) as db:
                user = db.table("users").get(self._query_filter)
                if hex_id not in user["credentials"]:
                    raise ValueError(
                        "hex_id",
                        "The provided credential ID was not found in user context",
                    )
                db.table("credentials").update(
                    validated_data.dict(exclude_none=True), Query().id == hex_id
                )

                return hex_id

    @validate_call
    async def search(
        self, name: constr(strip_whitespace=True, min_length=0) = Field(...)
    ):
        def search_name(s):
            return name in s

        async with TinyDB(**self.db_params) as db:
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
        in_q = lambda s: q in s
        async with TinyDB(**self.db_params) as db:
            matches = db.table("credentials").search(
                (Query().id.test(in_q)) | (Query().friendly_name.test(in_q))
            )
            return _create_credentials_mapping(matches)
