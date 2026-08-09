import subprocess


class NetworkScanner:
    @staticmethod
    def get_listening_services():
        """Returns a list of active listening ports and the process name."""
        try:
            # -t: TCP, -u: UDP, -l: listening, -n: numeric, -p: process
            output = subprocess.check_output(["sudo", "ss", "-tulnp"], text=True)
            lines = output.splitlines()
            # Filter for lines that indicate a listening socket
            services = [line for line in lines if "LISTEN" in line]
            return services
        except Exception as e:
            return [f"Error accessing network statistics: {e}"]
