import os
import unittest
from unittest.mock import patch, MagicMock
from security_sentinel.watcher import SecuritySentinelHandler

class TestSecuritySentinelHandler(unittest.TestCase):

    @patch('security_sentinel.watcher.os.path.exists')
    @patch('security_sentinel.watcher.shutil.move')
    def test_quarantine_file_moves_file(self, mock_shutil_move, mock_path_exists):
        mock_path_exists.side_effect = [False, True]  # Quarantine dir does not exist, file exists
        handler = SecuritySentinelHandler()
        handler.quarantine_file('/path/to/file.txt', 'file.txt')
        mock_shutil_move.assert_called_once_with('/path/to/file.txt', '/app/quarantine/file.txt')

    @patch('security_sentinel.watcher.open', new_callable=unittest.mock.mock_open, read_data='AWS_SECRET_ACCESS_KEY=abc123')
    @patch('security_sentinel.watcher.SecuritySentinelHandler.quarantine_file')
    def test_inspect_file_detects_leak(self, mock_quarantine_file, mock_open):
        handler = SecuritySentinelHandler()
        handler.inspect_file('/path/to/file.txt', 'file.txt')
        mock_quarantine_file.assert_called_once_with('/path/to/file.txt', 'file.txt')

    @patch('security_sentinel.watcher.requests.post')
    def test_trigger_spiderfoot_calls_api(self, mock_requests_post):
        handler = SecuritySentinelHandler()
        handler.trigger_spiderfoot('192.168.1.1')
        mock_requests_post.assert_called_once_with('http://osint-spiderfoot:5001/api/scan/start', data={'target': '192.168.1.1', 'type': 'IP'})

    @patch('security_sentinel.watcher.os.path.exists')
    @patch('security_sentinel.watcher.open', new_callable=unittest.mock.mock_open, read_data='No sensitive data here.')
    def test_inspect_file_no_leak(self, mock_open, mock_path_exists):
        mock_path_exists.return_value = True
        handler = SecuritySentinelHandler()
        handler.inspect_file('/path/to/file.txt', 'file.txt')
        # No quarantine should be called
        handler.quarantine_file.assert_not_called()

if __name__ == '__main__':
    unittest.main()