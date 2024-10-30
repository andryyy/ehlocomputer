from loguru import logger
from config import defaults
from config.database import *

__all__ = [
    "TinyDB",
    "Query",
    "Document",
    "TINYDB_PARAMS",
    "defaults",
    "logger",
]

logger.add(
    f"logs/application.log",
    level=defaults.LOG_LEVEL,
    colorize=False,
    rotation=defaults.LOG_FILE_ROTATION,
    retention=defaults.LOG_FILE_RETENTION,
    format=lambda _: defaults.CLUSTER_PEERS_ME,
    serialize=True,
)

if defaults.LOG_LEVEL != "DEBUG":

    def sink(_):
        return

    logger.debug = sink
