#!/usr/bin/env python3
import os, sys, time, logging
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security_sentinel.watcher import SentinelWatcher

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def main():
    watch_target = sys.argv[1] if len(sys.argv) > 1 else "./monitored"
    quarantine_target = sys.argv[2] if len(sys.argv) > 2 else "./quarantine"
    os.makedirs(watch_target, exist_ok=True)
    os.makedirs(quarantine_target, exist_ok=True)

    watcher = SentinelWatcher(watch_dir=watch_target, quarantine_dir=quarantine_target)
    watcher.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        watcher.stop()

if __name__ == "__main__":
    main()
