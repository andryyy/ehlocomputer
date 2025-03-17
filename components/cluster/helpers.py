import asyncio
import re
import socket

from components.database import IN_MEMORY_DB
from components.logs import logger
from components.models.cluster import LocalPeer, RemotePeer, IPvAnyAddress, Role
from components.utils import to_unique_sorted_str_list, ensure_list
from contextlib import closing


class Peers:
    def __init__(self, peers):
        self.remotes = dict()

        for peer in peers:
            if not peer.get("is_self", False):
                _peer = RemotePeer(**peer)
                self.remotes[_peer.name] = _peer

        self.local = LocalPeer(**next(peer for peer in peers if peer.get("is_self")))
        self._peers = peers

    def get_offline_peers(self):
        return [p for p in self.remotes if p not in self.get_established()]

    def get_established(self, names_only: bool = True, include_local: bool = False):
        peers = []
        for peer, peer_data in self.remotes.items():
            if peer_data._fully_established == True:
                if names_only:
                    peers.append(peer_data.name)
                else:
                    peers.append(peer_data)

        if include_local:
            if names_only:
                peers.append(self.local.name)
            else:
                peers.append(self.local)

        if names_only:
            return sorted(peers)
        return sorted(peers, key=lambda peer: peer.name)

    def get_remote_peer_ip(
        self, name: str, ip_version: str | list = ["ip4", "ip6", "nat_ip4"]
    ):
        def _select_best_ip(peer):
            return (
                str(getattr(peer, "ip4"))
                or str(getattr(peer, "ip6"))
                or str(getattr(peer, "nat_ip4"))
            )

        def _get_ips(peer, ip_version):
            return [
                str(ip) for key in ensure_list(ip_version) if (ip := getattr(peer, key))
            ]

        peer = self.remotes.get(name)
        if peer:
            if ip_version == "best":
                return _select_best_ip(peer)
            return _get_ips(peer, ip_version)

    def remote_ips(self):
        for name in self.remotes:
            for ip in self.get_remote_peer_ip(
                name=name, ip_version=["ip4", "ip6", "nat_ip4"]
            ):
                yield ip

    def get_remote_peer_name(self, ip):
        for peer_data in self.remotes.values():
            if ip in peer_data._all_ips_as_str:
                return peer_data.name


def elect_leader(peers_instance: Peers) -> None:
    def _destroy():
        peers_instance.local.leader = None
        peers_instance.local.role = Role.FOLLOWER
        peers_instance.local.swarm = ""

    n_eligible_peers = len(peers_instance.get_established(include_local=True))
    n_all_peers = len(peers_instance.remotes) + 1  # + self

    if not (n_eligible_peers >= (51 / 100) * n_all_peers):
        logger.info("Cannot elect leader node, not enough peers")
        _destroy()
        return

    leader, started = min(
        (
            (peer, peer_data.started)
            for peer, peer_data in peers_instance.remotes.items()
            if peer_data._fully_established
        ),
        key=lambda x: x[1],
        default=(None, float("inf")),
    )

    if peers_instance.local.started < started:
        if peers_instance.local.leader != peers_instance.local.name:
            logger.info("This node has been elected as the leader.")
            peers_instance.local.leader = peers_instance.local.name
            peers_instance.local.role = Role.LEADER

    else:
        if peers_instance.remotes[leader].leader == "?CONFUSED":
            _destroy()
            logger.info(
                f"""Potential leader node '{leader}' is still in the
election process or confused; waiting."""
            )
            return

        if peers_instance.remotes[leader].leader != leader:
            _destroy()
            logger.warning(
                f"Potential leader node '{leader}' reports a different leader; waiting"
            )
            return

        if peers_instance.local.leader != leader:
            peers_instance.local.leader = leader
            peers_instance.local.role = Role.FOLLOWER
            logger.info(f"Elected node '{leader}' as the leader")

    if peers_instance.local.leader:
        peers_instance.local.swarm = ";".join(
            peers_instance.get_established(include_local=True)
        )
        peers_instance.local.swarm_complete = n_eligible_peers == n_all_peers

    logger.debug(f"Cluster size {n_eligible_peers}/{n_all_peers}")
