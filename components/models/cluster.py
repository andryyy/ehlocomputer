import asyncio
import socket

from components.cluster.ssl import get_ssl_context
from components.models import *
from components.utils.datetimes import ntime_utc_now
from config import defaults
from contextlib import closing


class Role(Enum):
    LEADER = 1
    FOLLOWER = 2


class ConnectionStatus(Enum):
    CONNECTED = 0
    REFUSED = 1
    SOCKET_REFUSED = 2
    ALL_AVAILABLE_FAILED = 3
    OK = 4
    OK_WITH_PREVIOUS_ERRORS = 5


class CritErrors(Enum):
    NOT_READY = "CRIT:NOT_READY"
    NO_SUCH_TABLE = "CRIT:NO_SUCH_TABLE"
    TABLE_HASH_MISMATCH = "CRIT:TABLE_HASH_MISMATCH"
    CANNOT_APPLY = "CRIT:CANNOT_APPLY"
    NOTHING_TO_COMMIT = "CRIT:NOTHING_TO_COMMIT"
    INVALID_FILE_PATH = "CRIT:INVALID_FILE_PATH"
    START_BEHIND_FILE_END = "CRIT:START_BEHIND_FILE_END"
    PEERS_MISMATCH = "CRIT:PEERS_MISMATCH"
    DOC_MISMATCH = "CRIT:DOC_MISMATCH"
    ZOMBIE = "CRIT:ZOMBIE"

    @property
    def response(self):
        return f"ACK {self.value}"


class LocalPeer(BaseModel):
    @model_validator(mode="before")
    @classmethod
    def pre_init(cls, data: Any) -> Any:
        if not data["ip4"] and not data["ip6"]:
            raise ValueError("Neither a IPv4 nor a IPv6 address was provided")
        return data

    @field_validator("is_self")
    def local_self_validator(cls, v):
        if v != True:
            raise ValueError("LocalPeer does not have is_self flag")
        return v

    is_self: bool
    name: constr(pattern=r"^[a-zA-Z0-9\-_\.]+$", min_length=3)
    ip4: IPvAnyAddress | None = None
    ip6: IPvAnyAddress | None = None
    cli_bindings: list[IPvAnyAddress] = defaults.CLUSTER_CLI_BINDINGS
    leader: str | None = None
    role: Role = Role.FOLLOWER
    swarm: str = ""
    started: float = ntime_utc_now()
    swarm_complete: bool = False

    @computed_field
    @property
    def _bindings_as_str(self) -> str:
        return [str(ip) for key in ("ip4", "ip6") if (ip := getattr(self, key))]

    @computed_field
    @property
    def _all_bindings_as_str(self) -> str:
        return [
            str(ip) for key in ("ip4", "ip6") if (ip := getattr(self, key))
        ] + self.cli_bindings

    @model_validator(mode="after")
    def cli_bindings_validator(self):
        for ip in self.cli_bindings:
            if ip == self.ip4 or ip == self.ip6:
                raise ValueError("CLI bindings overlap local bindings")
        return self


class Streams(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    out: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
    _in: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None


class RemotePeer(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @model_validator(mode="before")
    @classmethod
    def pre_init(cls, data: Any) -> Any:
        if not data["ip4"] and not data["ip6"]:
            raise ValueError("Neither a IPv4 nor a IPv6 address was provided")
        return data

    @field_validator("is_self")
    def local_self_validator(cls, v):
        if v:
            raise ValueError("RemotePeer has is_self flag")
        return v

    is_self: bool = False
    sending_lock: asyncio.Lock = asyncio.Lock()
    swarm: str = ""
    leader: str | None = None
    started: float | None = None
    name: constr(pattern=r"^[a-zA-Z0-9\-_\.]+$", min_length=3)
    ip4: IPvAnyAddress | None = None
    ip6: IPvAnyAddress | None = None
    nat_ip4: IPvAnyAddress | None = None
    streams: Streams = Streams()
    port: int = 2102

    def reset(self):
        self.streams._in = None
        self.streams.out = None
        self.leader = None
        self.started = None
        self.swarm = ""
        return self

    def _eval_ip(
        self,
    ) -> tuple[IPvAnyAddress | None, tuple[ConnectionStatus, dict]]:
        errors = dict()
        peer_ips = [ip for ip in [self.ip4, self.ip6] if ip is not None]
        for ip in peer_ips:
            with closing(
                socket.socket(
                    socket.AF_INET if ip.version == 4 else socket.AF_INET6,
                    socket.SOCK_STREAM,
                )
            ) as sock:
                sock.settimeout(defaults.CLUSTER_PEERS_TIMEOUT)
                connection_return = sock.connect_ex((str(ip), self.port))
                if connection_return != 0:
                    errors[ip] = (
                        ConnectionStatus.SOCKET_REFUSED,
                        socket.errno.errorcode.get(connection_return),
                    )
                else:
                    if errors:
                        return ip, (ConnectionStatus.OK_WITH_PREVIOUS_ERRORS, errors)
                    return ip, (ConnectionStatus.OK, errors)
        else:
            return None, (ConnectionStatus.ALL_AVAILABLE_FAILED, errors)

    async def connect(
        self,
        ip: IPvAnyAddress | None = None,
    ) -> tuple[
        tuple[asyncio.StreamReader, asyncio.StreamWriter] | None,
        tuple[ConnectionStatus, Any],
    ]:
        if not self.streams.out:
            if not ip:
                ip, status = self._eval_ip()
                if not ip:
                    return None, status
            try:
                self.streams.out = await asyncio.open_connection(
                    str(ip), self.port, ssl=get_ssl_context("client")
                )
            except ConnectionRefusedError as e:
                return None, (ConnectionStatus.REFUSED, e)

        return self.streams.out, (ConnectionStatus.CONNECTED, None)

    @computed_field
    @property
    def _all_ips_as_str(self) -> str:
        return [str(ip) for key in ("ip4", "ip6") if (ip := getattr(self, key))]

    @computed_field
    @property
    def _fully_established(self) -> str:
        return (
            True
            if self.streams.out
            and self.streams._in
            and self.swarm
            and self.started
            and self.leader
            else False
        )
