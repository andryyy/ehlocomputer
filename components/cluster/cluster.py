from config.defaults import CLUSTER_PEERS
from components.cluster import Cluster

cluster = Cluster(peers=CLUSTER_PEERS, port=2102)
