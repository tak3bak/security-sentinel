"""
Nomadik Security Sentinel - Core Utility & Logging Library (sflib.py)
Provides secure logging wrappers, credential sanitization, and runtime helpers.
Fixes Code Scanning Alert #95 (CWE-532) and modern Python regex syntax compatibility.
"""

from __future__ import annotations

import copy
import logging
import re
from typing import Any, Mapping

# Configure module-level logger
logger = logging.getLogger("nomadik_sentinel")

# Pre-compiled raw regex patterns to prevent Python 3.12+ SyntaxError/DeprecationWarning
_SENSITIVE_KEYS = re.compile(
    r"(?i)^(api[_-]?key|token|access[_-]?token|refresh[_-]?token|bearer|password|passwd|secret|client[_-]?secret|authorization)$"
)

_BEARER_PATTERN = re.compile(
    r"(?i)\b(Bearer\s+)[A-Za-z0-9\-._~+/]+=*",
)

_KEY_VALUE_PATTERN = re.compile(
    r"""(?ix)
    (?P<prefix>\b(?:api[_-]?key|password|secret|token|bearer)\s*[:=]\s*)
    (?P<delim>['"]?)
    (?P<secret>[^'"\s,;&]+)
    (?P=delim)
    """
)

MASK = "[REDACTED]"


def sanitize_value(key: str, value: Any) -> Any:
    """Recursively scrub sensitive keys and token formats from data structures."""
    if _SENSITIVE_KEYS.search(str(key)):
        return MASK

    if isinstance(value, str):
        return sanitize_string(value)

    if isinstance(value, Mapping):
        return {k: sanitize_value(k, v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        sanitized_list = [sanitize_value(key, item) for item in value]
        return type(value)(sanitized_list)

    return value


def sanitize_string(text: str) -> str:
    """Scrub embedded secrets, Authorization headers, and key-value pairs from strings."""
    if not isinstance(text, str):
        return text

    # Mask Bearer tokens: 'Bearer eyJhb...' -> 'Bearer [REDACTED]'
    scrubbed = _BEARER_PATTERN.sub(r"\1" + MASK, text)

    # Mask embedded key/value assignments: 'api_key=xyz123' -> 'api_key=[REDACTED]'
    scrubbed = _KEY_VALUE_PATTERN.sub(r"\g<prefix>\g<delim>" + MASK + r"\g<delim>", scrubbed)

    return scrubbed


def sanitize_payload(payload: Any) -> Any:
    """Entry point for scrubbing arbitrary payloads (dict, list, string, or primitive)."""
    if isinstance(payload, Mapping):
        clean = copy.deepcopy(payload)
        return {k: sanitize_value(k, v) for k, v in clean.items()}
    if isinstance(payload, (list, tuple, set)):
        return type(payload)([sanitize_payload(item) for item in payload])
    if isinstance(payload, str):
        return sanitize_string(payload)
    return payload


class SentinelLoggerAdapter(logging.LoggerAdapter):
    """
    LoggerAdapter that automatically filters and redacts sensitive data
    prior to delegating to standard logging handlers.
    """

    def process(self, msg: Any, kwargs: Any) -> tuple[Any, Any]:
        scrubbed_msg = sanitize_string(str(msg)) if isinstance(msg, str) else sanitize_payload(msg)

        # Scrub any structured context passed via extra kwargs
        if "extra" in kwargs and isinstance(kwargs["extra"], Mapping):
            kwargs["extra"] = sanitize_payload(kwargs["extra"])

        return scrubbed_msg, kwargs


# Export default wrapped logger instance
secure_logger = SentinelLoggerAdapter(logger, {})


def log_debug(message: Any, **kwargs: Any) -> None:
    """Safe debug logger wrapper."""
    secure_logger.debug(message, **kwargs)


def log_info(message: Any, **kwargs: Any) -> None:
    """Safe info logger wrapper."""
    secure_logger.info(message, **kwargs)


def log_warning(message: Any, **kwargs: Any) -> None:
    """Safe warning logger wrapper."""
    secure_logger.warning(message, **kwargs)


def log_error(message: Any, **kwargs: Any) -> None:
    """Safe error logger wrapper."""
    secure_logger.error(message, **kwargs)
