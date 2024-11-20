from config import defaults
from loguru import logger


logger.add(
    f"logs/application.log",
    level=defaults.LOG_LEVEL,
    colorize=False,
    rotation=defaults.LOG_FILE_ROTATION,
    retention=defaults.LOG_FILE_RETENTION,
    format=lambda _: defaults.NODENAME,
    serialize=True,
)

if defaults.LOG_LEVEL != "DEBUG":

    def sink(_):
        return

    logger.debug = sink
