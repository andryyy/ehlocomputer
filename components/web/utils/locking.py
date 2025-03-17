import base64
import json
import os
from components.cluster.cluster import cluster
from components.cluster.exceptions import ClusterHTTPException
from components.utils.cryptography import dict_digest_sha1
from components.utils.datetimes import ntime_utc_now
from components.utils import ensure_list
from components.logs import logger
from components.database import *


class ClusterLock:
    def __init__(self, tables: list | str, app: object | None = None):
        self.tables = ensure_list(tables)
        self.aenter_db_data = dict()
        self.lock_tasks = set()
        self.app = app

    @staticmethod
    def compare_tables(d1, d2):
        keys1 = set(d1.keys())
        keys2 = set(d2.keys())

        added = keys2 - keys1
        removed = keys1 - keys2
        common_keys = keys1 & keys2
        changed = {
            doc_id: (d1[doc_id], d2[doc_id])
            for doc_id in common_keys
            if d1[doc_id] != d2[doc_id]
        }

        if not changed and not added and not removed:
            return None

        return {
            "changed": changed,
            "added": {doc_id: d2[doc_id] for doc_id in added},
            "removed": {doc_id: d1[doc_id] for doc_id in removed},
        }

    async def __aenter__(self):
        try:
            await cluster.acquire_lock(self.tables)
        except Exception as e:
            if self.app:
                raise ClusterHTTPException(description=e)
            raise

        self.db_params = evaluate_db_params()

        async with TinyDB(**self.db_params) as db:
            for t in self.tables:
                self.aenter_db_data[t] = dict()
                self.aenter_db_data[t]["data"] = {
                    doc.doc_id: doc for doc in db.table(t).all()
                }
                self.aenter_db_data[t]["digest"] = dict_digest_sha1(
                    self.aenter_db_data[t]["data"]
                )

        return cluster

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        commit = False
        error = False

        async with TinyDB(**self.db_params) as db:
            ticket = CTX_TICKET.get()

            for t in self.tables:
                table_data = {doc.doc_id: doc for doc in db.table(t).all()}
                diff = self.compare_tables(self.aenter_db_data[t]["data"], table_data)

                if diff:
                    commit = True
                    async with cluster.receiving:
                        try:
                            if not IN_MEMORY_DB.get("enforce_commit", False):
                                apply_mode = "PATCHTABLE"
                                diff_json_bytes = json.dumps(diff).encode("utf-8")
                                apply_data = base64.b64encode(diff_json_bytes).decode(
                                    "utf-8"
                                )
                            else:
                                apply_mode = "FULLTABLE"
                                jb = json.dumps(table_data, sort_keys=True).encode(
                                    "utf-8"
                                )
                                apply_data = base64.b64encode(jb).decode("utf-8")

                            _, receivers = await cluster.send_command(
                                f"{apply_mode} {t}@{self.aenter_db_data[t]['digest']} {apply_data}",
                                "*",
                                ticket=ticket,
                            )
                            await cluster.await_receivers(
                                ticket, receivers, raise_err=True
                            )
                        except Exception as e:
                            error = e
                            logger.error(
                                f"<ClusterLock> command {apply_mode} failed for {ticket}: {error}"
                            )
                            break

                    if apply_mode == "FULLTABLE":
                        IN_MEMORY_DB["PEER_CRIT"] = dict()

            if error == False:
                if commit:
                    async with cluster.receiving:
                        try:
                            _, receivers = await cluster.send_command(
                                f"COMMIT", "*", ticket=ticket
                            )
                            await cluster.await_receivers(
                                ticket, receivers, raise_err=True
                            )
                            await dbcommit(self.tables)
                        except:
                            logger.error(f"<ClusterLock> failed to commit {ticket}")
                else:
                    os.unlink(self.db_params["filename"])

        await cluster.release(self.tables)

        if error:
            if self.app:
                raise ClusterHTTPException(description=error)
            raise error
