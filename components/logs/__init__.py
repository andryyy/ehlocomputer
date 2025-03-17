from components.logs import log
from config.defaults import (
    LOG_LEVEL,
    LOG_FILE_ROTATION,
    LOG_FILE_RETENTION,
    CLUSTER_PEERS,
)

logger = log.Logger()
logger.add(
    f"logs/application.log",
    level=LOG_LEVEL,
    colorize=False,
    max_size_mb=LOG_FILE_ROTATION,
    retention=LOG_FILE_RETENTION,
    text=lambda _: next(p["name"] for p in CLUSTER_PEERS if p.get("is_self")),
    serialize=True,
)
