import pytest
from security_sentinel.spiderfoot import SpiderfootClient

def test_spiderfoot_client_init():
    client = SpiderfootClient()
    assert client is not None
