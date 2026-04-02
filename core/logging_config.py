# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""Logging setup with file rotation for ArgoNet."""

import logging
import os
from datetime import datetime
from pathlib import Path


LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
MAX_LOG_FILES = 20
LOG_FORMAT = "%(asctime)s [%(levelname)s]: %(message)s"


def setup_logging(enable_file: bool = True) -> logging.Logger:
    """Configure logging with optional file output and rotation."""
    logger = logging.getLogger("argonet")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    # Stream handler (stderr, so it doesn't mix with stdout output)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.WARNING)
    stream_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(stream_handler)

    if enable_file:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            _rotate_logs(LOG_DIR, MAX_LOG_FILES)

            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            log_file = LOG_DIR / f"{timestamp}.log"
            file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            logger.addHandler(file_handler)

            # Restrict permissions on Unix
            try:
                os.chmod(str(log_file), 0o600)
            except (OSError, AttributeError):
                pass
        except OSError:
            pass

    return logger


def _rotate_logs(log_dir: Path, max_files: int) -> None:
    """Remove oldest log files if count exceeds max_files."""
    log_files = sorted(
        [f for f in log_dir.iterdir() if f.suffix == ".log" and f.is_file()],
        key=lambda f: f.stat().st_mtime,
    )
    while len(log_files) >= max_files:
        oldest = log_files.pop(0)
        try:
            oldest.unlink()
        except OSError:
            break
