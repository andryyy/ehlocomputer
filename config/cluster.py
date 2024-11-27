from config.defaults import CLUSTER_PEERS_ME
from utils.cluster import Cluster

cluster = Cluster(host=CLUSTER_PEERS_ME, port=2102)


class ClusterLock:
    def __init__(self, lock_name: str = "main"):
        self.lock_name = lock_name

    async def __aenter__(self):
        await cluster.acquire_lock(self.lock_name)
        return cluster

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await cluster.release(self.lock_name)
