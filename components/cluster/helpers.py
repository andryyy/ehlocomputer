import asyncio
import re
import socket
import ssl

from components.database import IN_MEMORY_DB
from components.logs import logger
from components.models import IPvAnyAddress
from components.utils import to_unique_sorted_str_list, ensure_list
from config import defaults
from contextlib import closing
from enum import Enum


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
    START_BEHIND_FILE_END = "ACK CRIT:START_BEHIND_FILE_END"
    NO_TRUST = "ACK CRIT:NO_TRUST"
    PEERS_MISMATCH = "ACK CRIT:PEERS_MISMATCH"
    DOC_MISMATCH = "ACK CRIT:DOC_MISMATCH"


class PeersHelper:
    def __init__(self, peers):
        self._validate_peers(peers)
        self.peers = peers
        local = next(peer for peer in peers if peer.get("self"))
        self.local_name = local["name"]
        self.local_bindings = [ip for key in ("ip4", "ip6") if (ip := local.get(key))]
        for cli_binding in ensure_list(defaults.CLUSTER_CLI_BINDINGS):
            assert (
                cli_binding not in self.local_bindings
            ), f"CLI binding {cli_binding} overlaps with binding"

    def _validate_peers(self, peers):
        seen_names = set()
        seen_ips = set()
        self_count = 0
        name_pattern = re.compile(r"^[a-zA-Z0-9\-_\.]+$")

        for peer in peers:
            name = peer.get("name")
            if not name or not name_pattern.match(name):
                raise ValueError(f"Invalid name format: {name}")

            if name in seen_names:
                raise ValueError(f"Duplicate peer name: {name}")
            seen_names.add(name)

            for ip_field in ["ip4", "ip6", "nat_ip4"]:
                ip = peer.get(ip_field)
                if ip:
                    try:
                        parsed_ip = IPvAnyAddress(ip)
                    except:
                        raise ValueError(f"Invalid IP detected: {ip}")
                    if ip in seen_ips:
                        raise ValueError(f"Duplicate IP detected: {ip}")
                    seen_ips.add(ip)

            if not peer.get("ip4") and not peer.get("ip6"):
                raise ValueError(f"No peer IP for node {name}")

            if peer.get("self"):
                self_count += 1

        if self_count != 1:
            raise ValueError(
                f"Exactly one node must be marked as self. Found {self_count}."
            )

    def get_ip(self, name: str, ip_version="*"):
        def _select_best_ip(peer):
            return peer.get("ip4") or peer.get("ip6") or peer.get("nat_ip4")

        def _get_ips(peer, ip_versions="*"):
            if ip_versions == "*":
                ip_versions = ["ip4", "ip6", "nat_ip4"]
            else:
                ip_versions = ensure_list(ip_versions)
            return [ip for key in ip_versions if (ip := peer.get(key))]

        for peer in self.peers:
            if peer["name"] != self.local_name and peer["name"] == name:
                if ip_version == "best":
                    return _select_best_ip(peer)
                return _get_ips(peer, ip_version)

    def get_names(self):
        return [peer["name"] for peer in self.peers if peer["name"] != self.local_name]

    def gen_get_ips(self):
        for name in self.get_names():
            for ip in self.get_ip(name=name, ip_version="*"):
                yield ip

    def get_name(self, ip):
        for peer in self.peers:
            if (
                ip
                in (
                    peer.get("ip4"),
                    peer.get("ip6"),
                    peer.get("nat_ip4"),
                )
                and peer["name"] != self.local_name
            ):
                return peer["name"]


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
    logger.debug(f"(← Receiving from {peer}): {msg}")


def log_tx(peer: str, msg: str, max_msg_len=200) -> None:
    msg = msg[:max_msg_len] + (msg[max_msg_len:] and "...")
    logger.debug(f"(→ Sending to {peer}): {msg}")


async def connect(Cluster, peer: str) -> bool:
    assert isinstance(peer, str)
    async with Cluster.locks["ESTABLISHING"][peer]:
        if peer not in Cluster.connections:
            Cluster.connections[peer] = {
                "meta": dict(),
                "requests": 0,
                "streams": set(),
                "_last_established": None,
            }

        if not Cluster.connections[peer]["streams"]:
            peer_ips = Cluster.peers.get_ip(name=peer, ip_version=["ip4", "ip6"])
            for ip in peer_ips:
                peer_ip = IPvAnyAddress(ip)
                with closing(
                    socket.socket(
                        socket.AF_INET if peer_ip.version == 4 else socket.AF_INET6,
                        socket.SOCK_STREAM,
                    )
                ) as sock:
                    sock.settimeout(defaults.CLUSTER_PEERS_TIMEOUT)
                    connection_return = sock.connect_ex((str(peer_ip), Cluster.port))
                    if connection_return != 0:
                        logger.warning(
                            f"{peer}: Connection to {str(peer_ip)} failed ({socket.errno.errorcode.get(connection_return)})"
                        )
                    else:
                        break
            else:
                logger.error(f"{peer}: All IPs ({peer_ips}) for peer failed")
                return False

            try:
                Cluster.connections[peer]["streams"] = await asyncio.open_connection(
                    str(peer_ip), Cluster.port, ssl=get_ssl_context("client")
                )
                Cluster.connections[peer]["_last_established"] = str(peer_ip)
            except ConnectionRefusedError:
                logger.error(f"{peer}[{str(peer_ip)}]: Connection refused")
                return False

        return True


def set_master_node(Cluster) -> None:
    def _destroy():
        Cluster.master_node = None
        Cluster.role = Role.SLAVE
        Cluster.swarm = None

    established = set(
        [k for k, v in Cluster.connections.items() if v["meta"] and v["streams"]]
    )
    n_online_peers = len(established) + 1
    n_all_peers = len(defaults.CLUSTER_PEERS)
    current_master_node = Cluster.master_node

    if not (n_online_peers >= (51 / 100) * n_all_peers):
        logger.info("Cannot elect leader node, not enough peers")
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

    if Cluster.started < started:
        if Cluster.master_node != Cluster.peers.local_name:
            logger.info("This node has been elected as the leader.")
            Cluster.master_node = Cluster.peers.local_name
            Cluster.role = Role.MASTER

    else:
        if Cluster.connections[master_node]["meta"]["master"] == "?CONFUSED":
            _destroy()
            logger.info(
                f"""Potential leader node '{master_node}' is still in the
election process or confused; waiting."""
            )
            return

        if Cluster.connections[master_node]["meta"]["master"] != master_node:
            _destroy()
            logger.warning(
                f"Potential leader node '{master_node}' reports a different leader; waiting"
            )
            return

        if Cluster.master_node != master_node:
            Cluster.master_node = master_node
            Cluster.role = Role.SLAVE
            logger.info(f"Elected node {Cluster.master_node} as the leader")

    meta_started = to_unique_sorted_str_list(
        data["meta"]["started"] for data in Cluster.connections.values() if data["meta"]
    )

    if Cluster.master_node:
        Cluster.swarm = ";".join(
            sorted(
                {
                    data["meta"]["name"]
                    for data in Cluster.connections.values()
                    if data.get("meta") and data.get("streams")
                }
                | {Cluster.peers.local_name}
            )
        )
        Cluster.swarm_complete = n_online_peers == n_all_peers

    logger.debug(f"Cluster size {n_online_peers}/{n_all_peers}")
