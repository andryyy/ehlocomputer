import logging
import json
import os
import time
import traceback
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
import re

SUCCESS_LEVEL = 25
CRITICAL_LEVEL = 50
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")
logging.addLevelName(CRITICAL_LEVEL, "CRITICAL")

# ANSI color codes for log levels
LOG_COLORS = {
    "DEBUG": "\033[94m",  # Blue
    "INFO": "\033[96m",  # Cyan
    "SUCCESS": "\033[92m",  # Green
    "WARNING": "\033[93m",  # Yellow
    "ERROR": "\033[91m",  # Red
    "CRITICAL": "\033[95m",  # Magenta
    "RESET": "\033[0m",  # Reset
    "BOLD": "\033[1m",  # Bold
}


class JSONFormatter(logging.Formatter):
    def __init__(self, text):
        super().__init__()
        self.text = text

    def format(self, record):
        exc_text = None
        if record.exc_info:
            exc_text = traceback.format_exc()

        log_entry = {
            "text": self.text,
            "record": {
                "elapsed": {
                    "repr": str(timedelta(seconds=record.relativeCreated / 1000)),
                    "seconds": record.relativeCreated / 1000,
                },
                "exception": exc_text,
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
        message_bold = f"{LOG_COLORS['BOLD']}{record.getMessage()}{LOG_COLORS['RESET']}"
        return f"{log_time} | {LOG_COLORS['BOLD']}{level_color}{record.levelname:<8}{LOG_COLORS['RESET']} | {record.funcName}:{record.lineno} - {message_bold}"


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

    def add(self, filepath, level, colorize, max_size_mb, retention, text, serialize):
        for handler in self.logger.handlers[:]:
            if isinstance(handler, RotatingFileHandler):
                self.logger.removeHandler(handler)
                handler.close()

        handler = RotatingFileHandler(
            filepath,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=retention,
            encoding="utf-8",
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

    def critical(self, message):
        self.logger.log(CRITICAL_LEVEL, message, exc_info=True, stacklevel=2)


logger = Logger()
