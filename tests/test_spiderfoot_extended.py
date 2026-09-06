from unittest.mock import patch
from requests.exceptions import RequestException
from security_sentinel.spiderfoot import SpiderfootClient

def test_spiderfoot_client_init():
    client = SpiderfootClient()
    assert client is not None

def test_spiderfoot_client_methods():
    client = SpiderfootClient()
    with patch("security_sentinel.spiderfoot.requests.post") as mock_post:
        mock_post.return_value.json.return_value = {"id": "scan_123"}
        mock_post.return_value.status_code = 200
        res = client.trigger_scan("127.0.0.1")
        assert res == {"id": "scan_123"}

    with patch("security_sentinel.spiderfoot.requests.get") as mock_get:
        mock_get.return_value.json.return_value = {"status": "FINISHED"}
        mock_get.return_value.status_code = 200
        assert client.check_scan_status("scan_123") == {"status": "FINISHED"}
        assert client.get_scan_results("scan_123") == {"status": "FINISHED"}

@patch("security_sentinel.spiderfoot.requests.post", side_effect=RequestException("Connection error"))
def test_trigger_scan_exception(mock_post):
    client = SpiderfootClient()
    res = client.trigger_scan("127.0.0.1")
    assert res is None

@patch("security_sentinel.spiderfoot.requests.get", side_effect=RequestException("Status error"))
def test_check_scan_status_exception(mock_get):
    client = SpiderfootClient()
    res = client.check_scan_status("scan_123")
    assert res is None

@patch("security_sentinel.spiderfoot.requests.get", side_effect=RequestException("Results error"))
def test_get_scan_results_exception(mock_get):
    client = SpiderfootClient()
    res = client.get_scan_results("scan_123")
    assert res is None
