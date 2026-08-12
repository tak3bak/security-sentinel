#!/usr/bin/env python3
import sys
import ipaddress
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def block_ip(ip_str: str) -> bool:
    """
    Validates the IP address and securely adds a UFW deny rule using subprocess.
    """
    try:
        # Validate IP format to prevent injection and malformed rules
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        logging.error(f"Invalid IP address provided: '{ip_str}'")
        return False

    # Construct command array (shell=False prevents command injection)
    cmd = ["ufw", "deny", "from", str(ip_obj)]

    try:
        logging.info(f"Executing mitigation rule: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )
        logging.info(f"Successfully blocked IP {ip_obj}: {result.stdout.strip()}")
        return True
    except FileNotFoundError:
        logging.error("Execution failed: 'ufw' utility is not installed or not in PATH.")
        return False
    except subprocess.CalledProcessError as e:
        logging.error(f"UFW command failed with exit code {e.returncode}: {e.stderr.strip()}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logging.error("Usage: python mitigate.py <IP_ADDRESS>")
        sys.exit(1)

    target_ip = sys.argv[1]
    success = block_ip(target_ip)
    sys.exit(0 if success else 1)
