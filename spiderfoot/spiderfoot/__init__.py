import sys
import os

# Resolve parent directory paths
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sflib import SpiderFootLib
from spiderfoot.db import SpiderFootDb
from spiderfoot.helpers import SpiderFootHelpers

class SpiderFoot(SpiderFootLib, SpiderFootHelpers):
    """Unified engine combining SpiderFoot core logic with utility helpers."""
    def __init__(self, opts=None):
        if opts is None:
            opts = {}
        if not isinstance(opts, dict):
            raise TypeError("options must be a dict")
        super().__init__(opts)

__all__ = ["SpiderFoot", "SpiderFootDb", "SpiderFootHelpers"]
