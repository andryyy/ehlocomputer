from components.logs import logger
from components.models.cluster import LocalPeer, RemotePeer
from components.utils import ensure_list


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
