import time
import json
import os
import requests
from hybrid_crypto import HybridEncryption


class SentinelLogShipper:
    """Lightweight remote agent that encrypts local telemetry using the server's

    RSA Public Key and ships it to the Sentinel Ingress Endpoint.
    """

    def __init__(self, endpoint_url: str, public_key_path: str, context: str = "sentinel_v1_telemetry"):
        self.endpoint_url = endpoint_url
        self.context = context

        if not os.path.exists(public_key_path):
            raise FileNotFoundError(f"Public key not found at {public_key_path}")

        with open(public_key_path, "rb") as f:
            pub_pem = f.read()

        self.crypto = HybridEncryption(public_key_pem=pub_pem)

    def ship_log(self, log_event: dict | str) -> bool:
        """Encrypts a single log payload and posts it to the ingress endpoint."""
        if isinstance(log_event, dict):
            payload_str = json.dumps(log_event)
        else:
            payload_str = log_event

        # Encrypt with RSA-OAEP + AES-256-GCM
        encrypted_payload = self.crypto.encrypt(
            payload_str,
            associated_data=self.context.encode("utf-8")
        )

        try:
            response = requests.post(
                self.endpoint_url,
                json={"payload": encrypted_payload, "context": self.context},
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            print(f"[!] Transmission failed: {e}")
            return False


if __name__ == "__main__":
    PUB_KEY = os.path.expanduser("~/security-sentinel/keys/sentinel_public.pem")
    ENDPOINT = "http://127.0.0.1:8080/api/v1/telemetry"

    print("[*] Initializing Sentinel Log Shipper Agent...")
    shipper = SentinelLogShipper(endpoint_url=ENDPOINT, public_key_path=PUB_KEY)

    # Sample active defense telemetry event
    sample_event = {
        "agent_id": "edge-node-01",
        "timestamp": time.time(),
        "rule_id": 100201,
        "description": "Unauthorized SSH brute-force attempt detected",
        "src_ip": "192.168.1.150",
        "action": "ip_quarantined"
    }

    print("[*] Encrypting and shipping telemetry payload...")
    success = shipper.ship_log(sample_event)

    if success:
        print("[+] Log successfully encrypted and ingested by Sentinel Endpoint!")
    else:
        print("[-] Ingestion failed.")
