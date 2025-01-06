from config.defaults import CLUSTER_PEERS_ME
from config.logs import logger
from config.database import TinyDB, TINYDB_PARAMS
from utils.cluster import Cluster
from utils.helpers import ensure_list
from utils.datetimes import ntime_utc_now
from tools import evaluate_db_params
from deepdiff import DeepDiff, Delta
import os
import base64

cluster = Cluster(host=CLUSTER_PEERS_ME, port=2102)


class ClusterLock:
    def __init__(self, tables: list | str):
        self.tables = ensure_list(tables)
        self.aenter_db_data = dict()

    async def __aenter__(self):
        await cluster.acquire_lock(self.tables)
        self.db_params = evaluate_db_params()

        async with TinyDB(**self.db_params) as db:
            for t in self.tables:
                self.aenter_db_data[t] = db.table(t).all()

        return cluster

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        async with TinyDB(**self.db_params) as db:
            ticket = str(ntime_utc_now())

            for t in self.tables:
                table_data = db.table(t).all()

                diff = DeepDiff(
                    self.aenter_db_data[t],
                    table_data,
                    ignore_order=True,
                    report_repetition=True,
                    view="tree",
                )

                if diff:
                    table_delta = Delta(diff)
                    delta_string = base64.b64encode(table_delta.dumps()).decode("utf-8")
                    async with cluster.receiving:
                        try:
                            _, receivers = await cluster.send_command(
                                f"APPLY {t} {delta_string}", "*", ticket=ticket
                            )
                            await cluster._await_receivers(
                                ticket, receivers, raise_on_error=True
                            )
                        except:
                            logger.error(f"<ClusterLock> failed to apply {ticket}")

            async with cluster.receiving:
                try:
                    _, receivers = await cluster.send_command(
                        f"COMMIT", "*", ticket=ticket
                    )
                    await cluster._await_receivers(
                        ticket, receivers, raise_on_error=True
                    )
                    os.rename(self.db_params["filename"], TINYDB_PARAMS["filename"])
                except:
                    logger.error(f"<ClusterLock> failed to commit {ticket}")

        await cluster.release(self.tables)
