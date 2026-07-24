import time
import queue
import threading

from sentinel_domain_score import DomainReputationScorer
from sentinel_osint import SentinelOSINT
from audit_writer import AuditWriter

class RealTimeSentinel:
    def __init__(self):
        self.event_queue = queue.Queue()
        self.domain_scorer = DomainReputationScorer()
        self.ip_enricher = SentinelOSINT()
        self.audit = AuditWriter()
        self.running = True

    def submit_event(self, event):
        self.event_queue.put(event)

    def process_event(self, event):
        intel = {}

        # IP enrichment
        if "ip" in event:
            intel["ip_osint"] = self.ip_enricher.enrich_ip(event["ip"])

        # Domain enrichment + scoring
        if "domain" in event:
            domain_intel = self.domain_scorer.score(event["domain"])
            intel["domain_osint"] = domain_intel
            self.audit.write(event, domain_intel)

        return intel

    def worker(self):
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
                self.process_event(event)
            except queue.Empty:
                continue

    def start(self):
        thread = threading.Thread(target=self.worker, daemon=True)
        thread.start()
        return thread


# Example usage
if __name__ == "__main__":
    sentinel = RealTimeSentinel()
    sentinel.start()

    # Simulated incoming events
    sentinel.submit_event({"domain": "google.com", "source": "sentinel"})
    sentinel.submit_event({"ip": "8.8.8.8", "source": "sentinel"})

    # Keep running
    while True:
        time.sleep(1)
