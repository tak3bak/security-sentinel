import asyncio
import pytest
from app.osint import surface_scan

def test_rejects_oversized_hostname():
    with pytest.raises(ValueError):
        asyncio.run(surface_scan("a" * 254))
