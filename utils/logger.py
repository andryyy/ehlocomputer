import logging
import json
import os
import time
from datetime import datetime, timedelta
from logging.handlers import TimedRotatingFileHandler
import re

SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

# ANSI color codes for log levels
LOG_COLORS = {
    "DEBUG": "\033[94m",  # Blue
    "INFO": "\033[92m",  # Green
    "SUCCESS": "\033[96m",  # Cyan
    "WARNING": "\033[93m",  # Yellow
    "ERROR": "\033[91m",  # Red
    "RESET": "\033[0m",  # Reset
}


class JSONFormatter(logging.Formatter):
    def __init__(self, text):
        super().__init__()
        self.text = text

    def format(self, record):
        log_entry = {
            "text": self.text,
            "record": {
                "elapsed": {
                    "repr": str(timedelta(seconds=record.relativeCreated / 1000)),
                    "seconds": record.relativeCreated / 1000,
                },
                "exception": record.exc_text if record.exc_info else None,
                "extra": record.__dict__.get("extra", {}),
                "file": {"name": record.filename, "path": record.pathname},
                "function": record.funcName,
                "level": {
                    "icon": "✅"
                    if record.levelno == SUCCESS_LEVEL
                    else "ℹ️"
                    if record.levelno == logging.INFO
                    else "⚠️",
                    "name": record.levelname,
                    "no": record.levelno,
                },
                "line": record.lineno,
                "message": record.getMessage(),
                "module": record.module,
                "name": record.name,
                "process": {"id": record.process, "name": record.processName},
                "thread": {"id": record.thread, "name": record.threadName},
                "time": {
                    "repr": datetime.utcfromtimestamp(record.created).isoformat()
                    + "+00:00",
                    "timestamp": record.created,
                },
            },
        }
        return json.dumps(log_entry)


class PlainTextFormatter(logging.Formatter):
    def format(self, record):
        log_time = datetime.utcfromtimestamp(record.created).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]
        level_color = LOG_COLORS.get(record.levelname, LOG_COLORS["RESET"])
        relative_path = os.path.relpath(record.pathname, start=os.getcwd())
        return f"{log_time} | {level_color}{record.levelname:<8}{LOG_COLORS['RESET']} | {relative_path}:{record.funcName}:{record.lineno} - {record.getMessage()}"


def parse_rotation(rotation):
    match = re.match(
        r"(\d+)\s*(seconds|minutes|hours|days|weeks)", rotation, re.IGNORECASE
    )
    if match:
        value, unit = match.groups()
        return {
            "seconds": "S",
            "minutes": "M",
            "hours": "H",
            "days": "D",
            "weeks": "W",
        }[unit.lower()], int(value)
    return "D", 1


class Logger:
    def __init__(self):
        self.logger = logging.getLogger("custom_logger")
        self.logger.setLevel(logging.DEBUG)

        # Adding stdout handler
        stdout_handler = logging.StreamHandler()
        stdout_handler.setLevel(logging.DEBUG)
        stdout_handler.setFormatter(PlainTextFormatter())
        self.logger.addHandler(stdout_handler)

    def add(self, filepath, level, colorize, rotation, retention, text, serialize):
        rotation_unit, rotation_value = parse_rotation(rotation)
        handler = TimedRotatingFileHandler(
            filepath, when=rotation_unit, interval=rotation_value, backupCount=retention
        )
        handler.setLevel(level)
        handler.setFormatter(JSONFormatter(text(None)))
        self.logger.addHandler(handler)

    def log(self, level, message):
        self.logger.log(level, message, stacklevel=2)

    def info(self, message):
        self.logger.info(message, stacklevel=2)

    def warning(self, message):
        self.logger.warning(message, stacklevel=2)

    def error(self, message):
        self.logger.error(message, stacklevel=2)

    def debug(self, message):
        self.logger.debug(message, stacklevel=2)

    def success(self, message):
        self.logger.log(SUCCESS_LEVEL, message, stacklevel=2)


logger = Logger()
