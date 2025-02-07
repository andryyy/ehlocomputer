import base64
import json
import os

from config.database import *
from config.defaults import CLUSTER_PEERS_ME
from config.logs import logger
from deepdiff import DeepDiff, Delta
from hashlib import sha256
from tools import evaluate_db_params
from utils.cluster import Cluster
from utils.datetimes import ntime_utc_now
from utils.helpers import ensure_list
from quart import current_app
from werkzeug.exceptions import HTTPException

cluster = Cluster(host=CLUSTER_PEERS_ME, port=2102)


class ClusterHTTPException(HTTPException):
    def __init__(self, description=None):
        super().__init__(description)
        self.code = 999


class ClusterLock:
    def __init__(self, tables: list | str):
        self.tables = ensure_list(tables)
        self.aenter_db_data = dict()

    async def __aenter__(self):
        try:
            await cluster.acquire_lock(self.tables)
        except Exception as e:
            if current_app:
                raise ClusterHTTPException(description=e)
            raise

        self.db_params = evaluate_db_params()

        async with TinyDB(**self.db_params) as db:
            for t in self.tables:
                self.aenter_db_data[t] = dict()
                self.aenter_db_data[t]["data"] = {
                    doc.doc_id: doc for doc in db.table(t).all()
                }
                self.aenter_db_data[t]["json_bytes"] = json.dumps(
                    self.aenter_db_data[t]["data"], sort_keys=True
                ).encode("utf-8")
                self.aenter_db_data[t]["hash"] = sha256(
                    self.aenter_db_data[t]["json_bytes"]
                ).hexdigest()

        return cluster

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        commit = False
        error = False

        async with TinyDB(**self.db_params) as db:
            ticket = str(ntime_utc_now())

            for t in self.tables:
                table_data = {doc.doc_id: doc for doc in db.table(t).all()}
                diff = DeepDiff(
                    self.aenter_db_data[t]["data"],
                    table_data,
                    ignore_order=False,
                    report_repetition=True,
                    view="tree",
                )

                if diff:
                    commit = True
                    async with cluster.receiving:
                        try:
                            if not IN_MEMORY_DB.get("enforce_commit", False):
                                apply_mode = "PATCHTABLE"
                                table_delta = Delta(diff)
                                apply_data = base64.b64encode(
                                    table_delta.dumps()
                                ).decode("utf-8")
                            else:
                                apply_mode = "FULLTABLE"
                                jb = json.dumps(table_data, sort_keys=True).encode(
                                    "utf-8"
                                )
                                apply_data = base64.b64encode(jb).decode("utf-8")

                            _, receivers = await cluster.send_command(
                                f"{apply_mode} {t}@{self.aenter_db_data[t]['hash']} {apply_data}",
                                "*",
                                ticket=ticket,
                            )
                            await cluster.await_receivers(
                                ticket, receivers, raise_on_error=True
                            )
                        except Exception as e:
                            error = e
                            logger.error(
                                f"<ClusterLock> command {apply_mode} failed for {ticket}: {error}"
                            )
                            break

                    if apply_mode == "FULLTABLE":
                        IN_MEMORY_DB["peer_critical"] = dict()

            if commit and error == False:
                async with cluster.receiving:
                    try:
                        _, receivers = await cluster.send_command(
                            f"COMMIT", "*", ticket=ticket
                        )
                        await cluster.await_receivers(
                            ticket, receivers, raise_on_error=True
                        )
                        os.rename(self.db_params["filename"], TINYDB_PARAMS["filename"])
                    except:
                        logger.error(f"<ClusterLock> failed to commit {ticket}")

        await cluster.release(self.tables)

        if error:
            if current_app:
                raise ClusterHTTPException(description=error)
            raise error
