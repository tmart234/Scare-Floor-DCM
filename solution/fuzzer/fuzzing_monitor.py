from boofuzz.monitors import BaseMonitor
import subprocess

class FlagExposureMonitor(BaseMonitor):
    """Custom monitor to detect flag exposure via log file"""
    def __init__(self, log_path="/var/log/flag_exposed.log"):
        super().__init__()
        self.log_path = log_path
        
    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check for flag after each test case"""
        try:
            result = subprocess.check_output(
                ['grep', 'HTB{', self.log_path],
                stderr=subprocess.DEVNULL
            )
            if result:
                fuzz_data_logger.log_fail("Flag exposed in logs!")
                return False
        except subprocess.CalledProcessError:
            # No flag found - normal case
            pass
        return True

    def get_crash_synopsis(self):
        """Return last crash details"""
        try:
            with open(self.log_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return "No crash log available"
