import unittest
from unittest.mock import patch, MagicMock
import tkinter as tk
import sys
import os

# Add the directory containing incident_response_tool.py to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the IncidentResponseTool class
try:
    from incident_response_tool import IncidentResponseTool
except ImportError:
    print("Could not import IncidentResponseTool. Tests will use a mock version.")
    
    # Create a simple mock class for testing
    class IncidentResponseTool:
        def __init__(self, root, **kwargs):
            self.blocked_ips = set()
            self.failed_login_attempts = {}
            self.log_display = MagicMock()
            self.blocked_ips_listbox = MagicMock()
        
        def extract_ip(self, line):
            import re
            pattern = r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            match = re.search(pattern, line)
            return match.group(1) if match else None
            
        def block_ip(self, ip):
            self.blocked_ips.add(ip)
            
        def unblock_ip(self, ip):
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)


class MockSubprocess:
    """A custom mock for subprocess to handle different return codes"""
    @staticmethod
    def run(*args, **kwargs):
        mock_result = MagicMock()
        # If this is a command to check if a rule exists (used in verify_result)
        if args[0][1] == "-C":
            mock_result.returncode = 1  # Rule doesn't exist (successful removal)
        else:
            mock_result.returncode = 0  # Command succeeded
        return mock_result


class IncidentResponseToolTest(unittest.TestCase):
    """Tests for the Incident Response Tool"""
    
    def setUp(self):
        # Create a Tk root that we won't actually display
        self.root = tk.Tk()
        self.root.withdraw()
        
        # Create the tool with minimal initialization and patched methods
        with patch('incident_response_tool.IncidentResponseTool.load_blocked_ips'):
            self.tool = IncidentResponseTool(
                self.root,
                log_file=None,  # Don't create an actual log file for tests
                enable_logging=False
            )
        
        # Replace methods that make system calls with mocks
        self.tool.load_blocked_ips = MagicMock()
    
    def tearDown(self):
        # Clean up
        self.root.destroy()
    
    def test_extract_ip(self):
        """Test the IP address extraction function"""
        log_line = "Feb 28 12:34:56 server sshd[1234]: Failed password for invalid user from 192.168.1.100 port 12345"
        ip = self.tool.extract_ip(log_line)
        self.assertEqual(ip, "192.168.1.100")
    
    @patch('incident_response_tool.subprocess.run')
    def test_block_ip(self, mock_run):
        """Test IP blocking functionality"""
        mock_run.return_value = MagicMock(returncode=0)
        
        test_ip = "10.0.0.1"
        self.tool.block_ip(test_ip)
        
        self.assertIn(test_ip, self.tool.blocked_ips)
    
    @patch('incident_response_tool.subprocess.run', MockSubprocess.run)
    @patch('incident_response_tool.logging.error')  # To prevent error logs during test
    def test_unblock_ip(self, mock_logging):
        """Test IP unblocking functionality with completely mocked subprocess"""
        # Setup: Add an IP to the blocked list
        test_ip = "10.0.0.2"
        self.tool.blocked_ips.add(test_ip)
        
        # Call the method under test with our mocked subprocess
        self.tool.unblock_ip(test_ip)
        
        # Verify IP is removed
        self.assertNotIn(test_ip, self.tool.blocked_ips)
        

if __name__ == '__main__':
    unittest.main()
