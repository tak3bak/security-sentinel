import unittest
from unittest.mock import patch, mock_open
from security_sentinel.file_inspector import SecuritySentinelHandler

class TestFileInspector(unittest.TestCase):

    @patch('builtins.open', new_callable=mock_open, read_data='AWS_SECRET_ACCESS_KEY=abc123')
    def test_inspect_file_leak_detection(self, mock_file):
        handler = SecuritySentinelHandler()
        handler.quarantine_file = patch('security_sentinel.file_inspector.SecuritySentinelHandler.quarantine_file').start()
        
        handler.inspect_file('test_file.txt', 'test_file.txt')
        
        handler.quarantine_file.assert_called_once_with('test_file.txt', 'test_file.txt')
        mock_file.assert_called_once_with('test_file.txt', 'r', errors='ignore')

    @patch('builtins.open', new_callable=mock_open, read_data='No sensitive data here.')
    def test_inspect_file_no_leak(self, mock_file):
        handler = SecuritySentinelHandler()
        handler.quarantine_file = patch('security_sentinel.file_inspector.SecuritySentinelHandler.quarantine_file').start()
        
        handler.inspect_file('test_file.txt', 'test_file.txt')
        
        handler.quarantine_file.assert_not_called()
        mock_file.assert_called_once_with('test_file.txt', 'r', errors='ignore')

    @patch('builtins.open', new_callable=mock_open, read_data='IP found: 192.168.1.1')
    @patch('security_sentinel.file_inspector.SecuritySentinelHandler.trigger_spiderfoot')
    def test_ip_extraction(self, mock_trigger_spiderfoot, mock_file):
        handler = SecuritySentinelHandler()
        
        handler.inspect_file('test_file.txt', 'test_file.txt')
        
        mock_trigger_spiderfoot.assert_called_once_with('192.168.1.1')
        mock_file.assert_called_once_with('test_file.txt', 'r', errors='ignore')

if __name__ == '__main__':
    unittest.main()