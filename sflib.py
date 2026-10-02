import io
import os
import sys
import time
import logging
import hashlib
import re


class SpiderFootLib:
    def __init__(self, opts, config=None):
        self.opts = opts
        self.config = config
        self._scanId = opts.get("__scanId", "")
        self.log = logging.getLogger(f"spiderfoot.{self.__class__.__name__}")

    def _sanitize_log_data(self, data: object) -> str:
        if data is None:
            return ""

        if isinstance(data, (dict, list, tuple)):
            try:
                import json
                raw_text = json.dumps(data, default=str)
            except Exception:
                raw_text = str(data)
        else:
            raw_text = str(data)

        # 1. Redact Authorization Bearer and Basic headers
        raw_text = re.sub(
            r"(?i)(bearer|basic)\s+[A-Za-z0-9\-._~+/]+=*",
            r"\g<1> [REDACTED]",
            raw_text
        )

        # 2. Redact key-value credentials (handles unquoted and quoted values)
        pattern = r"""(?i)(api[_-]?key|secret|token|password|passwd|pwd|authorization|auth|privkey|private[_-]?key)\s*[:=]\s*(?:(["'])(.*?)|([^\s,;]+))"""
        def _replace_kv(m):
            key = m.group(1)
            quote = m.group(2) or ""
            return f"{key}={quote}[REDACTED]{quote}"

        raw_text = re.sub(pattern, _replace_kv, raw_text)

        return raw_text

    def error(self, message: str) -> None:
        if not self.opts.get("__logging", True):
            return
        self.log.error(self._sanitize_log_data(message), extra={"scanId": self._scanId})

    def fatal(self, error: str) -> None:
        self.log.critical(
            self._sanitize_log_data(error), extra={"scanId": self._scanId}
        )

    def info(self, message: str) -> None:
        if not self.opts.get("__logging", True):
            return
        self.log.info(self._sanitize_log_data(message), extra={"scanId": self._scanId})

    def debug(self, message: str) -> None:
        if not self.opts.get("_debug", False):
            return
        if not self.opts.get("__logging", True):
            return
        msg_str = str(message)
        if any(k in msg_str.lower() for k in ["password", "passwd", "secret", "token", "api_key", "apikey"]):
            self.log.debug("[SENSITIVE DATA REDACTED]", extra={"scanId": self._scanId})
            return
        clean_msg = self._sanitize_log_data(msg_str)
        self.log.debug("%s", clean_msg, extra={"scanId": self._scanId})

    def hashstring(self, string: str) -> str:
        if isinstance(string, str):
            return hashlib.sha256(string.encode("utf-8")).hexdigest()
        return hashlib.sha256(string).hexdigest()

    def cachePut(self, label: str, data: str) -> None:
        if not label or not data:
            return
        pathLabel = hashlib.sha224(label.encode("utf-8")).hexdigest()
        cacheFile = os.path.join(self.opts.get("cache_dir", "/tmp"), pathLabel)
        with io.open(cacheFile, "w", encoding="utf-8", errors="ignore") as fp:
            if isinstance(data, list):
                for line in data:
                    if isinstance(line, str):
                        fp.write(line + "\n")
                    else:
                        fp.write(line.decode("utf-8") + "\n")
            elif isinstance(data, bytes):
                fp.write(data.decode("utf-8"))
            else:
                fp.write(str(data))

    def cacheGet(self, label: str, timeoutHrs: int) -> str:
        if not label:
            return None
        pathLabel = hashlib.sha224(label.encode("utf-8")).hexdigest()
        cacheFile = os.path.join(self.opts.get("cache_dir", "/tmp"), pathLabel)
        if not os.path.exists(cacheFile):
            return None
        if (time.time() - os.path.getmtime(cacheFile)) > (timeoutHrs * 3600):
            return None
        with io.open(cacheFile, "r", encoding="utf-8", errors="ignore") as fp:
            return fp.read()

SpiderFoot = SpiderFootLib
