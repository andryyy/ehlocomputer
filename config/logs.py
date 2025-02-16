from config import defaults
from utils.logger import logger


logger.add(
    f"logs/application.log",
    level=defaults.LOG_LEVEL,
    colorize=False,
    rotation=defaults.LOG_FILE_ROTATION,
    retention=defaults.LOG_FILE_RETENTION,
    text=lambda _: defaults.CLUSTER_NODENAME,
    serialize=True,
)
