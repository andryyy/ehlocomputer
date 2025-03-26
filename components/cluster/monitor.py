import asyncio
from contextlib import suppress

from config import defaults
from components.logs import logger
from components.utils.datetimes import ntime_utc_now
from components.cluster.leader import elect_leader
from components.cluster.exceptions import ZombiePeer


class Monitor:
    def __init__(self, cluster_instance: "Cluster"):
        self.cluster_instance = cluster_instance
        self.tasks = set()

    async def _ticket_worker(self):
        """
        This asynchronous method checks for locks on tables and releases them if existent. It also deletes the tickets from
        the cluster instance, which have exceeded the timeout threshold. It performs these checks every 10 seconds until
        a shutdown is set.

        There are no input parameters for this function and it does not return anything. It gives an output through logs or errors.
        """
        while not self.cluster_instance._shutdown.is_set():
            for table in self.cluster_instance.locks:
                ticket = self.cluster_instance.locks[table]["ticket"]
                table_locked = self.cluster_instance.locks[table]["lock"].locked()

                if (table_locked and not ticket) or (
                    ntime_utc_now() - float(ticket or "inf")
                ) > 20.0:
                    with suppress(RuntimeError):
                        self.cluster_instance.locks[table]["lock"].release()
                    self.cluster_instance.locks[table]["ticket"] = None
                    logger.error(
                        f"Force release of table '{table}': "
                        + f"Ticket: {ticket} / Lock status: {table_locked}"
                    )

            for t in self.cluster_instance.tickets.copy():
                if ntime_utc_now() - float(t) > (
                    defaults.CLUSTER_PEERS_TIMEOUT * len(defaults.CLUSTER_PEERS) + 10
                ):
                    with suppress(KeyError):
                        del self.cluster_instance.tickets[t]

            await asyncio.sleep(10)

    async def _cleanup_peer_connection(self, peer):
        """
        Clean up a peer connection. Warning logs are created for the peer removal. The cluster instance of peers is reset
        and if the shutdown is not set, leadership is elected and commands are sent to non-local peers.

        Args:
            peer: the peer for whom the connection needs to be cleaned up.
        """
        logger.warning(f"Removing {peer}")
        self.cluster_instance.peers.remotes[peer] = self.cluster_instance.peers.remotes[
            peer
        ].reset()
        if not self.cluster_instance._shutdown.is_set():
            async with self.cluster_instance.receiving:
                elect_leader(self.cluster_instance.peers)
                if self.cluster_instance.peers.local.swarm != "":
                    for p in self.cluster_instance.peers.local.swarm.split(";"):
                        if p != self.cluster_instance.peers.local.name:
                            try:
                                (
                                    ticket,
                                    receivers,
                                ) = await self.cluster_instance.send_command(
                                    "STATUS",
                                    p,
                                )
                            except ConnectionResetError:
                                pass

    async def _peer_worker(self, name):
        """
        The method works with the name as an input and evaluates the stream for the same. It also handles leader election
        and various exception handling regarding connection reset and timeouts.

        Args:
            name: the name for whom the peer works.
        """
        ireader, iwriter = self.cluster_instance.peers.remotes[name].streams._in
        timeout_c = 0
        c = -1

        logger.info(f"Evaluating stream for {name}")
        while not name in self.cluster_instance.peers.get_established():
            await asyncio.sleep(0.125)

        oreader, owriter = self.cluster_instance.peers.remotes[name].streams.out

        elect_leader(self.cluster_instance.peers)

        while True and timeout_c < 3:
            try:
                assert not all(
                    [
                        oreader.at_eof(),
                        ireader.at_eof(),
                        iwriter.is_closing(),
                        owriter.is_closing(),
                    ]
                )

                async with asyncio.timeout(defaults.CLUSTER_PEERS_TIMEOUT * 3):
                    iwriter.write(b"\x11")
                    await iwriter.drain()
                    res = await oreader.readexactly(1)
                    assert res == b"\x11"

                timeout_c = 0
                c += 0.25
                await asyncio.sleep(0.25)

                if not c % 5:
                    if (
                        not self.cluster_instance.peers.local.leader
                        or not self.cluster_instance.peers.local.swarm_complete
                    ):
                        try:
                            (
                                ticket,
                                receivers,
                            ) = await self.cluster_instance.send_command(
                                "STATUS",
                                "*"
                                if self.cluster_instance.peers.local.leader
                                and not self.cluster_instance.peers.local.swarm_complete
                                else name,
                            )
                        except ConnectionResetError:
                            break

                        async with self.cluster_instance.receiving:
                            elect_leader(self.cluster_instance.peers)
                            await self.cluster_instance.await_receivers(
                                ticket, receivers, raise_err=False, timeout=3
                            )
                    c = 0

            except TimeoutError:
                timeout_c += 1
                continue
            except (
                AssertionError,
                ConnectionResetError,
                asyncio.exceptions.IncompleteReadError,
            ):
                logger.error(f"Peer {name} failed")
                break

        if c != -1:
            try:
                iwriter.close()
                async with asyncio.timeout(0.1):
                    await iwriter.wait_closed()
            except (ConnectionResetError, TimeoutError):
                pass

            try:
                owriter.close()
                async with asyncio.timeout(0.1):
                    await owriter.wait_closed()
                await owriter.wait_closed()
            except (ConnectionResetError, TimeoutError):
                pass

    def _on_task_done(self, task: asyncio.Task):
        """
        Called when an asyncio Task is done. A cleanup peer connection task is created and the original task is removed
        from the set of tasks.

        Args:
            task: The task that was completed.
        """
        asyncio.create_task(self._cleanup_peer_connection(task.get_name()))
        self.tasks.discard(task)

    async def start_peer_monitoring(self, name):
        """
        Start monitoring a peer. If the name of the peer is already in the list of tasks, it raises a ZombiePeer exception
        and otherwise, the peer worker is created as a task with the peer’s name.

        Args:
            name: the name of the peer to monitor.
        """
        if name in [task.get_name() for task in self.tasks]:
            raise ZombiePeer(name)

        t = asyncio.create_task(self._peer_worker(name), name=name)
        self.tasks.add(t)
        t.add_done_callback(self._on_task_done)
