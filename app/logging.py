"""Logging utilities for the OData service.

Self-contained replacement for the previous ``orso.logging`` dependency.
``orso`` is no longer part of the fleet, and opteryx-core's ``opteryx.logging``
is not depended on here so this service stays importable independently of the
core package's logging module.

The public surface mirrors what the codebase used from ``orso.logging``:

* ``set_log_name(name)`` — set the default logger name used by ``get_logger()``.
* ``get_logger(name=None)`` — return a ``logging.Logger``; when ``name`` is
  omitted the configured default name is used.
* the ``AUDIT`` (80) and ``ALERT`` (90) custom levels and matching
  ``logger.audit(...)`` / ``logger.alert(...)`` methods, mirroring orso's
  levels. ``dict``/``bytes`` messages are JSON-encoded, matching orso so audit
  payloads keep serializing the same way.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from typing import Optional

__all__ = ["get_logger", "set_log_name", "AUDIT", "ALERT"]

_DEFAULT_LOG_NAME = "opteryx"

# Custom levels mirror orso.logging.levels.LEVELS (AUDIT=80, ALERT=90). Both sit
# above ERROR so audit/alert records emit regardless of the configured level.
AUDIT = 80
ALERT = 90


def _add_logging_level(level_name: str, level_num: int) -> None:
    """Register a custom level and a matching convenience method on Logger.

    Mirrors ``orso.logging.add_level``: the method JSON-encodes ``dict`` (and
    decodes ``bytes``) messages so audit payloads serialize the same way.
    """
    method_name = level_name.lower()

    def log_for_level(self: logging.Logger, message: Any, *args: Any, **kwargs: Any) -> None:
        if isinstance(message, dict):
            try:
                message = json.dumps(message)
            except Exception:
                message = str(message)
        if isinstance(message, bytes):
            message = message.decode()
        if self.isEnabledFor(level_num):
            self._log(level_num, message, args, stacklevel=2, **kwargs)

    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    if not hasattr(logging.getLoggerClass(), method_name):
        setattr(logging.getLoggerClass(), method_name, log_for_level)


# Register the custom levels/methods once at import time.
_add_logging_level("AUDIT", AUDIT)
_add_logging_level("ALERT", ALERT)


def set_log_name(name: str) -> None:
    """Set the default logger name returned by :func:`get_logger`.

    Args:
        name: Name applied to loggers requested without an explicit name.
    """
    global _DEFAULT_LOG_NAME
    _DEFAULT_LOG_NAME = name


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a logger instance.

    The returned logger has ``audit()`` and ``alert()`` methods in addition to
    the standard levels.

    Args:
        name: Optional logger name. When omitted, the name configured via
            :func:`set_log_name` (default ``"opteryx"``) is used.

    Returns:
        A standard library :class:`logging.Logger`.
    """
    return logging.getLogger(name or _DEFAULT_LOG_NAME)
