import subprocess


class FirewallManager:
    @staticmethod
    def block_ip(ip_address):
        """Drops all traffic from a specific malicious IP."""
        try:
            check = subprocess.run(
                ["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"],
                capture_output=True,
            )
            if check.returncode != 0:
                subprocess.run(
                    ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
                )
                return True
            return False
        except Exception as e:
            print(f"[!] Firewall Error: {e}")
            return False
