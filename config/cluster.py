from config.defaults import CLUSTER_PEERS_ME
from config.logs import logger
from config.database import TinyDB, TINYDB_PARAMS
from utils.cluster import Cluster
from tools import evaluate_db_params
from deepdiff import DeepDiff, Delta
import os
import base64

cluster = Cluster(host=CLUSTER_PEERS_ME, port=2102)


class ClusterLock:
    def __init__(self, lock_name: str = "main"):
        self.lock_name = lock_name

    async def __aenter__(self):
        await cluster.acquire_lock(self.lock_name)
        self.db_params = evaluate_db_params()

        async with TinyDB(**self.db_params) as db:
            self.aenter_db_data = db.table(self.lock_name).all()

        return cluster

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        async with TinyDB(**self.db_params) as db:
            db_data = db.table(self.lock_name).all()
            diff = DeepDiff(
                self.aenter_db_data,
                db_data,
                ignore_order=True,
                report_repetition=True,
                view="tree",
            )
            if diff:
                print(diff.to_json())
                table_delta = Delta(diff)
                delta_string = base64.b64encode(table_delta.dumps()).decode("utf-8")
                async with cluster.receiving:
                    try:
                        ticket, receivers = await cluster.send_command(
                            f"APPLY {self.lock_name} {delta_string}", "*"
                        )
                        await cluster._await_receivers(
                            ticket, receivers, raise_on_error=True
                        )
                        _, receivers = await cluster.send_command(
                            f"COMMIT", "*", ticket=ticket
                        )
                        await cluster._await_receivers(
                            ticket, receivers, raise_on_error=True
                        )
                        os.rename(self.db_params["filename"], TINYDB_PARAMS["filename"])
                    except:
                        logger.error("<ClusterLock> failed to commit")
            else:
                if TINYDB_PARAMS["filename"] != self.db_params["filename"]:
                    os.unlink(self.db_params["filename"])

        await cluster.release(self.lock_name)
