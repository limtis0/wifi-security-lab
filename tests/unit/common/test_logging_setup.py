from __future__ import annotations

import json
import logging
from pathlib import Path

from attacks.common.logging_setup import (
    ColorConsoleFormatter,
    JsonLineFormatter,
    configure_logging,
)


def _make_log_record(
    message: str = "test message",
    level: int = logging.INFO,
    exc_info: tuple | None = None,
) -> logging.LogRecord:
    record = logging.LogRecord(
        name="test_logger",
        level=level,
        pathname="test.py",
        lineno=1,
        msg=message,
        args=(),
        exc_info=exc_info,
    )
    return record


# --- JsonLineFormatter ---


class TestJsonLineFormatter:
    def test_produces_valid_json_with_expected_keys(self):
        formatter = JsonLineFormatter()
        record = _make_log_record("hello world")

        output = formatter.format(record)
        parsed = json.loads(output)

        assert "timestamp" in parsed
        assert parsed["level"] == "INFO"
        assert parsed["message"] == "hello world"

    def test_includes_exception_key_when_exc_info_present(self):
        formatter = JsonLineFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            record = _make_log_record("error occurred", exc_info=sys.exc_info())

        output = formatter.format(record)
        parsed = json.loads(output)

        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]


# --- ColorConsoleFormatter ---


class TestColorConsoleFormatter:
    def test_output_contains_message(self):
        formatter = ColorConsoleFormatter()
        record = _make_log_record("important event")

        output = formatter.format(record)

        assert "important event" in output


# --- configure_logging ---


class TestConfigureLogging:
    def test_creates_log_file_when_output_dir_provided(self, output_dir: Path):
        configure_logging("test_attack", output_dir=output_dir)

        log_file = output_dir / "test_attack.log"
        assert log_file.exists()

        # Cleanup: remove handlers to avoid affecting other tests
        logging.getLogger().handlers.clear()

    def test_no_file_handler_without_output_dir(self):
        configure_logging("test_attack", output_dir=None)

        root_logger = logging.getLogger()
        file_handlers = [
            handler for handler in root_logger.handlers
            if isinstance(handler, logging.FileHandler)
        ]

        assert len(file_handlers) == 0

        root_logger.handlers.clear()

    def test_calling_twice_does_not_stack_handlers(self, output_dir: Path):
        configure_logging("test_attack", output_dir=output_dir)
        handler_count_after_first = len(logging.getLogger().handlers)

        configure_logging("test_attack", output_dir=output_dir)
        handler_count_after_second = len(logging.getLogger().handlers)

        assert handler_count_after_second == handler_count_after_first

        logging.getLogger().handlers.clear()
