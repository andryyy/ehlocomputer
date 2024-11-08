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
        pass

    class create:
        def __init__(self, *args, **kwargs):
            self.db_params = evaluate_db_params(kwargs)
            self._enforce_uuid = kwargs.get("_enforce_uuid")

        @cluster_task("users_create_user", enforce_uuid=True)
        async def user(self, data: dict):
            validated_data = users_model.UserAdd.parse_obj(data).dict()

            if self._enforce_uuid:
                validated_data["id"] = self._enforce_uuid

            async with TinyDB(**self.db_params) as db:
                name_conflict = db.table("users").search(
                    Query().login == validated_data["login"]
                )
                if name_conflict:
                    raise ValueError("name", "The provided login name exists")
                db.table("users").insert(validated_data)

            return validated_data["id"]

        @cluster_task("users_create_credential", enforce_uuid=True)
        async def credential(data: dict, assign_user_id: str | None = None):
            validated_data = auth_model.AddCredential.parse_obj(data).dict()

            async with TinyDB(**self.db_params) as db:
                if assign_user_id:
                    user = db.table("users").get(Query().id == assign_user_id)
                    if not user:
                        raise ValueError(
                            "name",
                            "The provided user ID for auto assignment does not exist, credential was not created",
                        )

                db.table("credentials").insert(validated_data)

                if assign_user_id:
                    user["credentials"].append(validated_data["id"])
                    db.table("users").update(
                        {"credentials": user["credentials"]},
                        Query().id == assign_user_id,
                    )

            return validated_data["id"]

    class user:
        def __init__(self, *args, **kwargs):
            self.db_params = evaluate_db_params(kwargs)
            self.init_kwargs = kwargs

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

        @cluster_task("users_user_delete_credential")
        @validate_call
        async def delete_credential(
            self, hex_id: constr(pattern=r"^[0-9a-fA-F]+$", min_length=2)
        ):
            async with TinyDB(**self.db_params) as db:
                user = db.table("users").get(self._query_filter)
                if hex_id in user["credentials"]:
                    del user["credentials"][hex_id]
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

    async def exists(
        self, id: str | list | None = None, login: str | list | None = None
    ) -> bool:
        attr = users_model._Users_attr(id=id, login=login)
        ids = ensure_list(attr.id)
        logins = ensure_list(attr.login)

        async with TinyDB(**TINYDB_PARAMS) as db:
            matches = db.table("users").search(
                Query().id.one_of(ids) if ids else Query().login.one_of(logins)
            )
            if ids:
                return set([m["id"] for m in matches]) == set(ids)
            return set([m["login"] for m in matches]) == set(login)

    @validate_call
    async def search(self, q: constr(strip_whitespace=True, min_length=0) = Field(...)):
        in_q = lambda s: q in s
        async with TinyDB(**TINYDB_PARAMS) as db:
            matches = db.table("users").search(
                (Query().login.test(in_q)) | (Query().id.test(in_q))
            )

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
        async with TinyDB(**TINYDB_PARAMS) as db:
            matches = db.table("credentials").search(
                (Query().id.test(in_q)) | (Query().friendly_name.test(in_q))
            )
            return _create_credentials_mapping(matches)
