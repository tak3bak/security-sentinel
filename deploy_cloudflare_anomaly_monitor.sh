#!/usr/bin/env bash
# ==============================================================================
# Script: deploy_cloudflare_anomaly_monitor.sh
# Description: Installs zero-dependency Cloudflare Edge WAF Anomaly Monitor
#              into ~/.local/bin/cloudflare_anomaly_alert.py.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="${HOME}/.local/bin"
SCRIPT_FILE="${SCRIPT_DIR}/cloudflare_anomaly_alert.py"

echo "[+] Deploying Cloudflare Edge Anomaly Monitoring Pipeline..."

mkdir -p "${SCRIPT_DIR}"

cat << 'PYTHON_SCRIPT' > "${SCRIPT_FILE}"
#!/usr/bin/env python3
import os
import sys
import time
import json
import logging
import urllib.request
import urllib.error

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

CF_API_TOKEN = os.getenv("CF_API_TOKEN", "")
CF_ZONE_ID = os.getenv("CF_ZONE_ID", "")
POLL_INTERVAL_SEC = int(os.getenv("POLL_INTERVAL_SEC", "300"))
WAF_BLOCK_THRESHOLD = int(os.getenv("WAF_BLOCK_THRESHOLD", "50"))

if not CF_API_TOKEN or not CF_ZONE_ID:
    logging.error("Missing credentials: Export CF_API_TOKEN and CF_ZONE_ID environment variables.")
    sys.exit(1)

GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"

GRAPHQL_QUERY = """
query GetZoneAnalytics($zoneTag: String!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      httpRequests1mGroups(limit: 5, orderBy: [datetime_DESC]) {
        dimensions {
          datetime
        }
        sum {
          requests
          threats
          pageViews
        }
      }
      firewallEventsAdaptiveGroups(limit: 5, filter: {action: "block"}) {
        count
        dimensions {
          action
          clientAsn
        }
      }
    }
  }
}
"""

def query_cloudflare_metrics():
    payload = json.dumps({
        "query": GRAPHQL_QUERY,
        "variables": {"zoneTag": CF_ZONE_ID}
    }).encode("utf-8")

    req = urllib.request.Request(
        GRAPHQL_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": "Cloudflare-Anomaly-Monitor/1.0"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            data = json.loads(res.read().decode("utf-8"))
            if data.get("errors"):
                logging.error(f"Cloudflare GraphQL API Errors: {data['errors']}")
                return

            zones = data.get("data", {}).get("viewer", {}).get("zones", [])
            if not zones:
                logging.warning("No zone data returned for provided CF_ZONE_ID.")
                return

            zone_data = zones[0]
            fw_events = zone_data.get("firewallEventsAdaptiveGroups", [])
            total_blocks = sum(event.get("count", 0) for event in fw_events)

            logging.info(f"Cloudflare Edge Check Complete | Blocked Firewall Events: {total_blocks}")

            if total_blocks >= WAF_BLOCK_THRESHOLD:
                logging.warning(f"[ALERT] High WAF Block Threshold Breached! ({total_blocks} >= {WAF_BLOCK_THRESHOLD})")

    except urllib.error.HTTPError as e:
        logging.error(f"HTTP Error: {e.code} {e.reason}")
    except Exception as e:
        logging.error(f"Query Exception: {str(e)}")

def main():
    logging.info("Starting Cloudflare Edge Anomaly Monitoring Pipeline...")
    while True:
        query_cloudflare_metrics()
        time.sleep(POLL_INTERVAL_SEC)

if __name__ == "__main__":
    main()
PYTHON_SCRIPT

chmod +x "${SCRIPT_FILE}"

echo "[+] Cloudflare Edge Anomaly Monitor deployed successfully."
echo "[+] Executable: ${SCRIPT_FILE}"
