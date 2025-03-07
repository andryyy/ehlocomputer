from components.models.users import (
    AddCredential,
    CredentialPatch,
    CredentialRead,
    User,
    UserAdd,
    UserPatch,
    UserProfile,
    UserSession,
    constr,
    validate_call,
    UUID,
)
from components.utils import merge_deep, merge_models
from components.database import *
from components.cache import buster


def _create_credentials_mapping(credentials: dict):
    user_credentials = dict()
    for c in credentials:
        user_credentials.update({c["id"]: CredentialRead.parse_obj(c)})
    return user_credentials


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
async def create(data: dict):
    db_params = evaluate_db_params()
    create_user = UserAdd.parse_obj(data)

    async with TinyDB(**db_params) as db:
        if db.table("users").search(Query().login == create_user.login):
            raise ValueError("name", "The provided login name exists")
        insert_data = create_user.dict()
        db.table("users").insert(insert_data)

    for user_id in IN_MEMORY_DB["FORM_OPTIONS_CACHE"].copy():
        if "users" in IN_MEMORY_DB["FORM_OPTIONS_CACHE"][user_id]:
            del IN_MEMORY_DB["FORM_OPTIONS_CACHE"][user_id]["users"]

    return insert_data["id"]


@validate_call
async def get(user_id: UUID, join_credentials: bool = True):
    db_params = evaluate_db_params()

    async with TinyDB(**db_params) as db:
        user = User.parse_obj(db.table("users").get(Query().id == str(user_id)))
        credentials = db.table("credentials").search(
            (Query().id.one_of(user.credentials))
        )
        if join_credentials:
            user.credentials = _create_credentials_mapping(credentials)

        return user


@validate_call
async def delete(user_id: UUID):
    db_params = evaluate_db_params()
    user = await get(user_id=user_id, join_credentials=False)

    if not user:
        raise ValueError("name", "The provided user does not exist")

    async with TinyDB(**db_params) as db:
        print(len(db.table("users").all()))
        return
        db.table("credentials").remove(Query().id.one_of(user.credentials))
        deleted = db.table("users").remove(Query().id == str(user_id))
        buster(user["id"])
        return user["id"]


@validate_call
async def create_credential(user_id: UUID, data: dict):
    db_params = evaluate_db_params()
    credential = AddCredential.parse_obj(data)
    user = await get(user_id=user_id, join_credentials=False)

    if not user:
        raise ValueError("name", "The provided user does not exist")

    async with TinyDB(**db_params) as db:
        db.table("credentials").insert(credential.dict())
        user.credentials.append(credential.id)
        db.table("users").update(
            {"credentials": user.credentials},
            Query().id == str(user_id),
        )
        return credential.id


@validate_call
async def delete_credential(
    user_id: UUID, hex_id: constr(pattern=r"^[0-9a-fA-F]+$", min_length=2)
):
    db_params = evaluate_db_params()
    user = await get(user_id=user_id, join_credentials=False)

    if not user:
        raise ValueError("name", "The provided user does not exist")

    async with TinyDB(**db_params) as db:
        if hex_id in user.credentials:
            user.credentials.remove(hex_id)
            db.table("credentials").remove(Query().id == hex_id)
            db.table("users").update(
                {"credentials": user.credentials}, Query().id == str(user_id)
            )
            return hex_id


@validate_call
async def patch(user_id: UUID, data: dict):
    db_params = evaluate_db_params()
    patch_user = UserPatch.parse_obj(data)
    user = await get(user_id=user_id, join_credentials=False)

    if not user:
        raise ValueError("name", "The provided user does not exist")

    async with TinyDB(**db_params) as db:
        if db.table("users").get(
            (Query().login == patch_user.login) & (Query().id != str(user_id))
        ):
            raise ValueError("login", "The provided login name exists")

        orphaned_credentials = [
            c for c in user.credentials if c not in patch_user.credentials
        ]
        db.table("users").update(
            patch_user.dict(exclude_unset=True),
            Query().id == str(user_id),
        )
        db.table("credentials").remove(Query().id.one_of(orphaned_credentials))

        buster(user.id)
        return user.id


@validate_call
async def patch_profile(user_id: UUID, data: dict):
    db_params = evaluate_db_params()
    user = await get(user_id=user_id, join_credentials=False)

    if not user:
        raise ValueError("name", "The provided user does not exist")

    patch_data = UserProfile.model_validate(data)
    patched_user_profile = merge_models(user.profile, patch_data)

    async with TinyDB(**db_params) as db:
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
    user = await get(user_id=user_id, join_credentials=True)

    if not user:
        raise ValueError("name", "The provided user does not exist")

    if hex_id not in user.credentials:
        raise ValueError(
            "hex_id",
            "The provided credential ID was not found in user context",
        )

    async with TinyDB(**db_params) as db:
        patched_credential = CredentialPatch.model_validate(
            merge_deep(user.credentials[hex_id].dict(), data)
        )
        db.table("credentials").update(patched_credential.dict(), Query().id == hex_id)
        return hex_id


@validate_call
async def search(
    name: constr(strip_whitespace=True, min_length=0), join_credentials: bool = True
):
    db_params = evaluate_db_params()

    def search_name(s):
        return name in s

    async with TinyDB(**db_params) as db:
        matches = db.table("users").search(Query().login.test(search_name))

    return [
        await get(user["id"], join_credentials=join_credentials) for user in matches
    ]
