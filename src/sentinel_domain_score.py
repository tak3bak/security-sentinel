from datetime import datetime
from sentinel_domain_intel import DomainIntelProcessor
from sentinel_domain_osint import SentinelDomainOSINT

class DomainReputationScorer:
    def __init__(self):
        self.osint = SentinelDomainOSINT()
        self.processor = DomainIntelProcessor()

    def score(self, domain: str):
        raw = self.osint.enrich_domain(domain)["osint"]
        intel = self.processor.process(raw)

        score = 0
        factors = []

        # Age scoring
        if intel["creation_date"]:
            try:
                created = datetime.fromisoformat(intel["creation_date"].replace("Z", "+00:00"))
                age_days = (datetime.utcnow() - created).days

                if age_days < 30:
                    score += 40
                    factors.append("New domain (<30 days)")
                elif age_days < 180:
                    score += 20
                    factors.append("Young domain (<6 months)")
                else:
                    score -= 10
                    factors.append("Established domain")
            except:
                factors.append("Creation date parsing failed")

        # Registrar scoring
        if intel["registrar"]:
            registrar = intel["registrar"].lower()
            if "markmonitor" in registrar or "google" in registrar:
                score -= 20
                factors.append("Trusted registrar")
            else:
                score += 10
                factors.append("Uncommon registrar")

        # Nameserver scoring
        for ns in intel["nameservers"]:
            if "cloudflare" in ns.lower():
                score -= 10
                factors.append("Cloudflare NS (trusted)")
            elif "google" in ns.lower():
                score -= 10
                factors.append("Google NS (trusted)")
            else:
                score += 10
                factors.append(f"Unusual nameserver: {ns}")

        # IP scoring
        for ip in intel["ipv4"]:
            if ip.startswith("142.") or ip.startswith("8."):
                score -= 10
                factors.append(f"Known Google IP: {ip}")
            else:
                score += 15
                factors.append(f"Unusual IPv4: {ip}")

        # Subdomain scoring
        if len(intel["subdomains"]) > 20:
            score += 20
            factors.append("Large subdomain footprint")
        elif len(intel["subdomains"]) == 0:
            score += 5
            factors.append("No subdomains found")

        # Normalize score
        if score < 0:
            score = 0
        if score > 100:
            score = 100

        return {
            "domain": domain,
            "score": score,
            "risk_level": self.risk_label(score),
            "factors": factors,
            "intel": intel
        }

    def risk_label(self, score):
        if score >= 80:
            return "High Risk"
        if score >= 50:
            return "Medium Risk"
        return "Low Risk"


# Example usage
if __name__ == "__main__":
    scorer = DomainReputationScorer()
    result = scorer.score("google.com")
    print(result)
