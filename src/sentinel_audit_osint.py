from sentinel_domain_score import DomainReputationScorer
from audit_writer import AuditWriter

class SentinelAuditOSINT:
    def __init__(self):
        self.scorer = DomainReputationScorer()
        self.audit = AuditWriter()

    def process_event(self, event):
        if "domain" not in event:
            return

        intel = self.scorer.score(event["domain"])
        self.audit.write(event, intel)
        return intel


# Example usage
if __name__ == "__main__":
    engine = SentinelAuditOSINT()
    event = {"domain": "google.com", "source": "sentinel"}
    intel = engine.process_event(event)
    print(intel)
