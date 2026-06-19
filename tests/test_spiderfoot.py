import pytest
from unittest.mock import patch, Mock
from security_sentinel.spiderfoot import trigger_spiderfoot

@pytest.fixture
def mock_requests_post():
    with patch('security_sentinel.spiderfoot.requests.post') as mock_post:
        yield mock_post

def test_trigger_spiderfoot_success(mock_requests_post):
    mock_requests_post.return_value = Mock(status_code=200)
    target_ip = "192.168.1.1"
    
    trigger_spiderfoot(target_ip)
    
    mock_requests_post.assert_called_once_with(
        "http://osint-spiderfoot:5001/api/scan/start",
        data={'target': target_ip, 'type': 'IP'}
    )

def test_trigger_spiderfoot_failure(mock_requests_post):
    mock_requests_post.return_value = Mock(status_code=500)
    target_ip = "192.168.1.1"
    
    trigger_spiderfoot(target_ip)
    
    mock_requests_post.assert_called_once_with(
        "http://osint-spiderfoot:5001/api/scan/start",
        data={'target': target_ip, 'type': 'IP'}
    )