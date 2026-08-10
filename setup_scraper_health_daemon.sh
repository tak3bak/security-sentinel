#!/usr/bin/env bash
set -euo pipefail

DAEMON_DIR="${HOME}/.local/bin"
DAEMON_FILE="${DAEMON_DIR}/scraper_health_daemon.py"
SERVICE_DIR="${HOME}/.config/systemd/user"
SERVICE_FILE="${SERVICE_DIR}/scraper-health-daemon.service"

mkdir -p "${DAEMON_DIR}" "${SERVICE_DIR}"

cat << 'PYEOF' > "${DAEMON_FILE}"
#!/usr/bin/env python3
import os, sys, time, logging, subprocess, urllib.request, urllib.error

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')

CHECK_INTERVAL_SEC = int(os.getenv("CHECK_INTERVAL_SEC", "30"))
MAX_FAIL_THRESHOLD = int(os.getenv("MAX_FAIL_THRESHOLD", "3"))
TEST_TARGET_URL = os.getenv("TEST_TARGET_URL", "https://httpbin.org/ip")
SCRAPER_SERVICE_NAME = os.getenv("SCRAPER_SERVICE_NAME", "scraper-worker")
PROXY_LIST = [p.strip() for p in os.getenv("PROXY_LIST", "").split(",") if p.strip()]

class ScraperHealthDaemon:
    def __init__(self):
        self.consecutive_failures = 0
        self.current_proxy_index = 0

    def check_health(self) -> bool:
        proxy = PROXY_LIST[self.current_proxy_index] if PROXY_LIST else None
        try:
            req = urllib.request.Request(TEST_TARGET_URL, headers={"User-Agent": "Mozilla/5.0"})
            if proxy:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))
                res = opener.open(req, timeout=10)
            else:
                res = urllib.request.urlopen(req, timeout=10)
            return res.getcode() in (200, 204)
        except Exception as e:
            logging.error(f"Health check failed: {str(e)}")
            return False

    def trigger_remediation(self):
        logging.warning(f"Threshold reached ({MAX_FAIL_THRESHOLD}). Restarting service...")
        subprocess.run(["systemctl", "--user", "restart", SCRAPER_SERVICE_NAME], capture_output=True)

    def run(self):
        logging.info("Starting Scraper Health Daemon...")
        while True:
            if self.check_health():
                self.consecutive_failures = 0
            else:
                self.consecutive_failures += 1
                if PROXY_LIST:
                    self.current_proxy_index = (self.current_proxy_index + 1) % len(PROXY_LIST)
            if self.consecutive_failures >= MAX_FAIL_THRESHOLD:
                self.trigger_remediation()
                self.consecutive_failures = 0
            time.sleep(CHECK_INTERVAL_SEC)

if __name__ == "__main__":
    ScraperHealthDaemon().run()
PYEOF

chmod +x "${DAEMON_FILE}"

cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=Scraper Health and Proxy Rotation Daemon
After=network.target

[Service]
Type=simple
ExecStart=${DAEMON_FILE}
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
