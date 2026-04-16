"""Structured logging setup — console (WARNING) + file (DEBUG)."""

import logging
import sys

import config


def setup_logging() -> None:
    """Configure the root logger for CyberSentinel."""
    root = logging.getLogger("cybersentinel")
    root.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.DEBUG))

    # Avoid duplicate handlers on repeated calls
    if root.handlers:
        return

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler — DEBUG level, captures everything
    try:
        fh = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        root.addHandler(fh)
    except OSError:
        # If log file can't be created (e.g., read-only filesystem), skip it
        pass

    # Console handler — WARNING level only (Rich handles user-facing output)
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.WARNING)
    ch.setFormatter(formatter)
    root.addHandler(ch)
