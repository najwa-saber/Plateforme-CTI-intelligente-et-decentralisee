"""Logging configuration: single-line structured logs, secrets never logged."""
from __future__ import annotations

import logging
import sys


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - trivial
        if not hasattr(record, "request_id"):
            record.request_id = "-"
        return True


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(name)s [rid=%(request_id)s] %(message)s")
    )
    handler.addFilter(_RequestIdFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
    for noisy in ("urllib3", "web3", "asyncio", "multipart", "pymisp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
