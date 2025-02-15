import ssl
from config import defaults
from config.logs import logger
from enum import Enum
from utils.helpers import to_unique_sorted_str_list


class Role(Enum):
    MASTER = 1
    SLAVE = 0


class CritErrors(Enum):
    NOT_READY = "ACK CRIT:NOT_READY"
    NO_SUCH_TABLE = "ACK CRIT:NO_SUCH_TABLE"
    TABLE_HASH_MISMATCH = "ACK CRIT:TABLE_HASH_MISMATCH"
    CANNOT_APPLY = "ACK CRIT:CANNOT_APPLY"
    NOTHING_TO_COMMIT = "ACK CRIT:NOTHING_TO_COMMIT"
    INVALID_FILE_PATH = "ACK CRIT:INVALID_FILE_PATH"
    NO_TRUST = "ACK CRIT:NO_TRUST"
    PEERS_MISMATCH = "ACK CRIT:PEERS_MISMATCH"
    DOC_MISMATCH = "ACK CRIT:DOC_MISMATCH"


def get_ssl_context(type_value: str):
    if type_value == "client":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    elif type_value == "server":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    else:
        raise Exception("Unknown type_value")

    context.load_cert_chain(
        certfile=defaults.TLS_CERTFILE, keyfile=defaults.TLS_KEYFILE
    )
    context.load_verify_locations(cafile=defaults.TLS_CA)
    context.check_hostname = False
    context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def log_rx(peer: str, msg: str, max_msg_len=200) -> None:
    msg = msg[:max_msg_len] + (msg[max_msg_len:] and "...")
    logger.debug(f"(Rx) {defaults.CLUSTER_PEERS_ME} ← {peer}: {msg}")


def log_tx(peer: str, msg: str, max_msg_len=200) -> None:
    msg = msg[:max_msg_len] + (msg[max_msg_len:] and "...")
    logger.debug(f"(Tx) {defaults.CLUSTER_PEERS_ME} → {peer}: {msg}")


def set_master_node(Cluster) -> None:
    def _destroy():
        Cluster.master_node = None
        Cluster.role = Role.SLAVE
        Cluster.connected_nodes = None

    established = set(
        [k for k, v in Cluster.connections.items() if v["meta"] and v["streams"]]
    )
    n_online_peers = len(established) + 1
    n_all_peers = len(defaults.CLUSTER_PEERS_THEM) + 1
    current_master_node = Cluster.master_node

    if not (n_online_peers >= (51 / 100) * n_all_peers):
        logger.info("<set_master_node> skipping election, not enough peers")
        _destroy()
        return

    master_node, started = min(
        (
            (peer, float(data["meta"]["started"]))
            for peer, data in Cluster.connections.items()
            if data["meta"]
        ),
        key=lambda x: x[1],
        default=(None, float("inf")),
    )

    if Cluster.started < started:  # donkey elects itCluster
        if Cluster.master_node != defaults.CLUSTER_PEERS_ME:
            logger.info(
                f"<set_master_node> elected self ({defaults.CLUSTER_PEERS_ME}) as master"
            )
            Cluster.master_node = defaults.CLUSTER_PEERS_ME
            Cluster.role = Role.MASTER

    else:
        if Cluster.connections[master_node]["meta"]["master"] == "?CONFUSED":
            _destroy()
            logger.info(
                f"<set_master_node> potential master {master_node} is still confused, waiting"
            )
            return

        if Cluster.connections[master_node]["meta"]["master"] != master_node:
            _destroy()
            logger.warning(
                f"<set_master_node> not electing {master_node}:"
                + "node reports different master (are we still joining or changed our swarm size?) - "
                + "waiting"
            )
            return

        if Cluster.master_node != master_node:
            Cluster.master_node = master_node
            Cluster.role = Role.SLAVE
            logger.info(
                f"<set_master_node> elected foreign peer {Cluster.master_node} as master"
            )

    meta_started = to_unique_sorted_str_list(
        data["meta"]["started"] for data in Cluster.connections.values() if data["meta"]
    )

    if Cluster.master_node:
        Cluster.connected_nodes = ";".join(
            data["meta"]["bind"]
            for data in Cluster.connections.values()
            if data["meta"] and data["streams"]
        )

    logger.debug(f"<set_master_node> cluster size {n_online_peers}/{n_all_peers}")
