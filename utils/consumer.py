import json
import os
import re
import redis
import shlex
import tarfile
import time

from config import defaults
from config import logger
from config.database import Query, TinyDB, r
from datetime import datetime, timezone
from models import realms as realms_model
from pathlib import Path
from quart import session
from secrets import token_bytes
from secrets import token_urlsafe
from subprocess import Popen
from threading import Thread
from utils.helpers import flatten, utc_now_as_str


def consumer(cache_ttl=2000, max_lock=800):  # in ms
    try:
        r.xgroup_create(name="ehlotalk", groupname="workers", id=0, mkstream=True)
    except redis.ResponseError:  # Ignore existing group
        pass

    i_am = os.getpid()

    while True:
        message = r.xreadgroup(
            count=1,
            groupname="workers",
            consumername=os.getpid(),
            streams={"ehlotalk": ">"},
            block=0,
        )

        if message:
            try:
                # Lock will auto expire after max_lock ms
                while not r.set("LOCK", os.getpid(), px=max_lock, nx=True):
                    continue

                tasks = flatten(message.get("ehlotalk", []))
                for task in tasks:
                    _id, data = task
                    match data:
                        case {
                            "command": "filewrite",
                            "filename": fname,
                            "data": fdata,
                        }:
                            # Write payload to file
                            Path(fname).write_text(fdata)

                            # Try to sync file with fs
                            os.sync()

                            r.set(f"unread:{fname}", 1)
                            r.set(fname, fdata, px=cache_ttl)

                        case {
                            "command": "fileread",
                            "filename": fname,
                            "ticket": ticket,
                        }:
                            # Extending the unread key to disable caching for a while after a write
                            if r.getex(f"unread:{fname}", px=800) or not r.getex(
                                fname, px=cache_ttl
                            ):
                                r.set(fname, Path(fname).read_text(), px=cache_ttl)
                                logger.info("Uncached file read")
                            else:
                                logger.success("Cached file read")
                            r.set(ticket, r.get(fname), px=cache_ttl)

                        case {
                            "command": "run_podman",
                        }:
                            if r.get(f"run_podman:{os.getppid()}"):
                                break

                            def run_podman():
                                logger.info("Starting podman")
                                args = shlex.split(
                                    f"{defaults.PODMAN_BINARY} system service --time=0 unix:///tmp/ehlopodman.sock"
                                )
                                proc = Popen(args)
                                proc.wait()

                            thread = Thread(
                                target=run_podman,
                                daemon=True,
                                name=f"podman",
                            )
                            thread.start()

                            i = 0
                            while (
                                not Path("/tmp/ehlopodman.sock").is_socket() or i > 50
                            ):
                                time.sleep(0.1)
                                i += 1
                                pass

                            if i > 50:
                                sys.exit("Could not start podman")

                            r.set(f"run_podman:{os.getppid()}", "1", ex=60)

                        case {
                            "command": "setup_realm",
                        }:
                            if r.get(f"setup_realm:{os.getppid()}"):
                                break

                            with TinyDB(path="realms/realms.json") as db:
                                c_table = db.table("realms")
                                if not c_table.all():
                                    # Create first realm
                                    first_realm = realms_model.RealmCreate(
                                        name="Default",
                                        default=True,
                                    )
                                    c_table.insert(first_realm.dict())

                                    # Create realm database file
                                    with TinyDB(
                                        path=f"realms/databases/{first_realm.id}"
                                    ) as db:
                                        db.table("_meta").insert(
                                            {"file_created": utc_now_as_str()}
                                        )

                                else:
                                    # Update realms to apply new schema, if any
                                    for realm in c_table.search(Query().bootstrapped == True):
                                        c_table.update(
                                            realms_model.RealmPatch.model_validate(
                                                realm
                                            ).dict(),
                                            (
                                                (Query().id == realm["id"])
                                                & (Query().bootstrapped == True)
                                            ),
                                        )
                                    logger.info("Updated bootstrapped realms")

                                if not c_table.get(Query().bootstrapped == True):
                                    # Not writing to logs
                                    print("°".join(["*" for n in range(15)]))
                                    bootstrap_token = token_urlsafe()
                                    print(
                                        "Bootstrap token, 120s valid."
                                        + "Restart application to generate a new token."
                                    )
                                    print(bootstrap_token)
                                    r.set(
                                        "setup_realm:bootstraptoken",
                                        bootstrap_token,
                                        ex=120,
                                        get=True,
                                    )
                                    print("°".join(["*" for n in range(15)]))

                            r.set(f"setup_realm:{os.getppid()}", "1", ex=60)

                        case _:
                            # Unknown command name
                            logger.error(f"{_id} - unknown command, dunno")

                    # Acknowledge our success
                    r.xack("ehlotalk", "workers", _id)

                    # Some garbage cleanup that only happens when the current time in s % 5 has no rest
                    if int(time.time()) % 5 == 0:
                        r.xtrim("ehlotalk", approximate=True, maxlen=100)

            except Exception as e:
                # Inform about an error
                logger.error(str(e))

            finally:
                # Always cleanup the lock
                r.delete("LOCK")
