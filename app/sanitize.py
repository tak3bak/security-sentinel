import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

# List of sensitive keys to redact from logs
SENSITIVE_KEYS = {"password", "token", "secret", "authorization", "api_key", "access_token"}

def sanitize_record(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively redact sensitive key values from dictionary payloads before logging.
    """
    if not isinstance(data, dict):
        return data

    sanitized = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in SENSITIVE_KEYS):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_record(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_record(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            sanitized[key] = value
    return sanitized

def log_safe_event(event_name: str, payload: Dict[str, Any]) -> None:
    """
    Logs events safely without exposing credentials or tokens in clear-text.
    """
    safe_payload = sanitize_record(payload)
    logger.info("Event: %s - Data: %s", event_name, safe_payload)
