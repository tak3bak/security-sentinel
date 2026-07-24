from spiderfoot_client import SpiderFootClient
import json

class SentinelDomainOSINT:
    def __init__(self):
        self.sf = SpiderFootClient()

        # Domain-focused modules
        self.modules = [
            "sfp_dnsresolve",
            "sfp_dns",
            "sfp_subdomains",
            "sfp_googlesearch",
            "sfp_bingsearch",
            "sfp_sslcert",
            "sfp_whois",
            "sfp_httphdrs"
        ]

    def enrich_domain(self, domain: str):
        try:
            results = self.sf.run_scan(domain, self.modules)
            return {
                "domain": domain,
                "osint": results
            }
        except Exception as e:
            return {
                "domain": domain,
                "error": str(e)
            }


# Example usage
if __name__ == "__main__":
    engine = SentinelDomainOSINT()
    enriched = engine.enrich_domain("google.com")
    print(json.dumps(enriched, indent=2))
from spiderfoot_client import SpiderFootClient
import json

class SentinelDomainOSINT:
    def __init__(self):
        self.sf = SpiderFootClient()

        # Domain-focused modules
        self.modules = [
            "sfp_dnsresolve",
            "sfp_dns",
            "sfp_subdomains",
            "sfp_googlesearch",
            "sfp_bingsearch",
            "sfp_sslcert",
            "sfp_whois",
            "sfp_httphdrs"
        ]

    def enrich_domain(self, domain: str):
        try:
            results = self.sf.run_scan(domain, self.modules)
            return {
                "domain": domain,
                "osint": results
            }
        except Exception as e:
            return {
                "domain": domain,
                "error": str(e)
            }


# Example usage
if __name__ == "__main__":
    engine = SentinelDomainOSINT()
    enriched = engine.enrich_domain("google.com")
    print(json.dumps(enriched, indent=2))
