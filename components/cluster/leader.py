from components.logs import logger
from components.models.cluster import Role


def elect_leader(peers: "Peers") -> None:
    def _destroy():
        peers.local.leader = None
        peers.local.role = Role.FOLLOWER
        peers.local.swarm = ""

    n_eligible_peers = len(peers.get_established(include_local=True))
    n_all_peers = len(peers.remotes) + 1  # + self

    if not (n_eligible_peers >= (51 / 100) * n_all_peers):
        logger.info("Cannot elect leader node, not enough peers")
        _destroy()
        return

    leader, started = min(
        (
            (peer, peer_data.started)
            for peer, peer_data in peers.remotes.items()
            if peer_data._fully_established
        ),
        key=lambda x: x[1],
        default=(None, float("inf")),
    )

    if peers.local.started < started:
        if peers.local.leader != peers.local.name:
            logger.info("This node has been elected as the leader.")
            peers.local.leader = peers.local.name
            peers.local.role = Role.LEADER

    else:
        if peers.remotes[leader].leader == "?CONFUSED":
            _destroy()
            logger.info(
                f"""Potential leader node '{leader}' is still in the
election process or confused; waiting."""
            )
            return

        if peers.remotes[leader].leader != leader:
            _destroy()
            logger.warning(
                f"Potential leader node '{leader}' reports a different leader; waiting"
            )
            return

        if peers.local.leader != leader:
            peers.local.leader = leader
            peers.local.role = Role.FOLLOWER
            logger.info(f"Elected node '{leader}' as the leader")

    if peers.local.leader:
        peers.local.swarm = ";".join(peers.get_established(include_local=True))
        peers.local.swarm_complete = n_eligible_peers == n_all_peers

    logger.debug(f"Cluster size {n_eligible_peers}/{n_all_peers}")
