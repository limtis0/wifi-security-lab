from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path


class JsonLineFormatter(logging.Formatter):
    """Formats log records as JSON lines for machine-parseable output."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class ColorConsoleFormatter(logging.Formatter):
    """Human-readable colored console output."""

    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[31;1m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S")
        return f"{color}[{timestamp}] [{record.levelname:>7}] [{record.name}]{self.RESET} {record.getMessage()}"


def configure_logging(attack_name: str, output_dir: Path | None = None) -> None:
    """Set up logging with console and optional JSON file handlers.

    Args:
        attack_name: Used to name the log file.
        output_dir: Directory for the JSON log file. If None, only console logging is configured.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Remove any existing handlers
    root_logger.handlers.clear()

    # Console handler: human-readable with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(ColorConsoleFormatter())
    root_logger.addHandler(console_handler)

    # File handler: JSON lines for machine parsing
    if output_dir is not None:
        log_file_path = output_dir / f"{attack_name}.log"
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonLineFormatter())
        root_logger.addHandler(file_handler)
