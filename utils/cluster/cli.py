import asyncio
from config.database import IN_MEMORY_DB
from tools.users import get as get_user, patch as patch_user, what_id


async def cli_processor(streams: tuple[asyncio.StreamReader, asyncio.StreamWriter]):
    try:
        reader, writer = streams
        while not reader.at_eof():
            cmd = await reader.readexactly(1)
            if cmd == b"\x97":
                data = await reader.readuntil(b"\n")
                login = data.strip().decode("utf-8")
                try:
                    user_id = await what_id(login=login)
                    user = await get_user(user_id=user_id)
                    if "system" not in user.acl:
                        user.acl.append("system")
                        from utils.cluster.http_lock import ClusterLock

                        async with ClusterLock("users"):
                            await patch_user(
                                user_id=user_id,
                                data={
                                    "login": login,
                                    "acl": user.acl,
                                    "credentials": list(user.credentials.keys()),
                                },
                            )
                        writer.write(b"\x01")
                    else:
                        writer.write(b"\x02")
                except Exception as e:
                    writer.write(b"\x03")
                await writer.drain()
            elif cmd == b"\x98":
                awaiting = dict()
                idx = 1
                for k, v in IN_MEMORY_DB.items():
                    if (
                        isinstance(v, dict)
                        and v.get("token_type") == "cli_confirmation"
                    ):
                        awaiting[idx] = (k, v["intention"])
                        idx += 1
                writer.write(f"{json.dumps(awaiting)}\n".encode("ascii"))
                await writer.drain()
            elif cmd == b"\x99":
                data = await reader.readexactly(14)
                confirmed = data.strip().decode("ascii")
                code = "%06d" % random.randint(0, 999999)
                IN_MEMORY_DB.get(confirmed, {}).update(
                    {"status": "confirmed", "code": code}
                )
                writer.write(f"{code}\n".encode("ascii"))
                await writer.drain()
    except Exception as e:
        if type(e) not in [
            asyncio.exceptions.IncompleteReadError,
            ConnectionResetError,
        ]:
            raise
    finally:
        writer.close()
        await writer.wait_closed()
