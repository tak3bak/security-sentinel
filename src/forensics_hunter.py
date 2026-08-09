import subprocess
import json


class ForensicsHunter:
    def __init__(self, api_key):
        self.api_key = api_key

    def hunt_attacker(self, ip_address):
        """
        Triggers a SpiderFoot scan against an identified malicious IP.
        This assumes spiderfoot-cli is installed on the system.
        """
        try:
            # Command to start a scan via SpiderFoot CLI
            # This identifies linked domains, netblocks, and known threat intel
            cmd = ["sfcli", "-s", ip_address, "-m", "sfp_ipinfo,sfp_threatintel"]
            result = subprocess.run(cmd, capture_output=True, text=True)

            return (
                f"[+] Forensic Hunt Initiated for {ip_address}: {result.stdout[:200]}"
            )
        except Exception as e:
            return f"[!] Forensic Hunt Failed: {e}"
