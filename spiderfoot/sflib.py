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

    def _sanitize_log_data(self, data: str) -> str:
        if not isinstance(data, str):
            return data
        pattern = r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]+)['"]?"
        return re.sub(pattern, r"\1=***REDACTED***", data)

    def error(self, message: str) -> None:
        if not self.opts.get("__logging", True):
            return
        self.log.error(self._sanitize_log_data(message), extra={"scanId": self._scanId})

    def fatal(self, error: str) -> None:
        self.log.critical(self._sanitize_log_data(error), extra={"scanId": self._scanId})

    def info(self, message: str) -> None:
        if not self.opts.get("__logging", True):
            return
        self.log.info(self._sanitize_log_data(message), extra={"scanId": self._scanId})

    def debug(self, message: str) -> None:
        if not self.opts.get("_debug", False):
            return
        if not self.opts.get("__logging", True):
            return
        self.log.debug(self._sanitize_log_data(message), extra={"scanId": self._scanId})

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
