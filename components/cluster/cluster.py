from config.defaults import CLUSTER_PEERS_ME
from components.cluster import Cluster


cluster = Cluster(host=CLUSTER_PEERS_ME, port=2102)
