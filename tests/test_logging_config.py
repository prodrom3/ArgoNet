"""Tests for core.logging_config module."""

import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.logging_config import _rotate_logs, setup_logging


class TestSetupLogging(unittest.TestCase):
    def setUp(self) -> None:
        # Clear handlers between tests
        logger = logging.getLogger("argonet")
        logger.handlers.clear()

    def test_returns_logger(self) -> None:
        logger = setup_logging(enable_file=False)
        self.assertIsInstance(logger, logging.Logger)
        self.assertEqual(logger.name, "argonet")

    def test_no_file_handler_when_disabled(self) -> None:
        logger = setup_logging(enable_file=False)
        file_handlers = [
            h for h in logger.handlers
            if isinstance(h, logging.FileHandler)
        ]
        self.assertEqual(len(file_handlers), 0)

    def test_idempotent(self) -> None:
        logger1 = setup_logging(enable_file=False)
        handler_count = len(logger1.handlers)
        logger2 = setup_logging(enable_file=False)
        self.assertEqual(len(logger2.handlers), handler_count)
        self.assertIs(logger1, logger2)


class TestRotateLogs(unittest.TestCase):
    def test_rotation_removes_oldest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            for i in range(5):
                (log_dir / f"test_{i}.log").write_text(f"log {i}")

            _rotate_logs(log_dir, max_files=3)
            remaining = list(log_dir.glob("*.log"))
            self.assertLessEqual(len(remaining), 3)

    def test_no_rotation_under_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            for i in range(2):
                (log_dir / f"test_{i}.log").write_text(f"log {i}")

            _rotate_logs(log_dir, max_files=5)
            remaining = list(log_dir.glob("*.log"))
            self.assertEqual(len(remaining), 2)

    def test_ignores_non_log_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            (log_dir / "notes.txt").write_text("not a log")
            (log_dir / "test.log").write_text("a log")

            _rotate_logs(log_dir, max_files=5)
            self.assertTrue((log_dir / "notes.txt").exists())


if __name__ == "__main__":
    unittest.main()
