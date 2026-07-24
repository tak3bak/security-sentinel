import re
from datetime import datetime

class DomainIntelProcessor:
    def __init__(self):
        pass

    def process(self, spiderfoot_results):
        intel = {
            "domain": None,
            "registrar": None,
            "whois_raw": None,
            "creation_date": None,
            "expiration_date": None,
            "nameservers": [],
            "ipv4": [],
            "ipv6": [],
            "subdomains": [],
        }

        for item in spiderfoot_results:
            t = item.get("type")
            d = item.get("data")

            # Domain name
            if t == "Domain Name" and intel["domain"] is None:
                intel["domain"] = d

            # Registrar
            if t == "Domain Registrar":
                intel["registrar"] = d

            # WHOIS raw
            if t == "Domain Whois":
                intel["whois_raw"] = d

                # Extract creation/expiration dates
                creation = re.search(r"Creation Date:\s*(.*)", d)
                expiry = re.search(r"Expir\w+ Date:\s*(.*)", d)

                if creation:
                    intel["creation_date"] = creation.group(1).strip()

                if expiry:
                    intel["expiration_date"] = expiry.group(1).strip()

            # Nameservers
            if t == "Internet Name" and "ns" in d.lower():
                intel["nameservers"].append(d)

            # IPv4
            if t == "IP Address":
                intel["ipv4"].append(d)

            # IPv6
            if t == "IPv6 Address":
                intel["ipv6"].append(d)

            # Subdomains
            if t == "Domain Name" and d != intel["domain"]:
                if d.endswith(intel["domain"]):
                    intel["subdomains"].append(d)

        return intel


# Example usage
if __name__ == "__main__":
    from sentinel_domain_osint import SentinelDomainOSINT

    engine = SentinelDomainOSINT()
    raw = engine.enrich_domain("google.com")["osint"]

    processor = DomainIntelProcessor()
    intel = processor.process(raw)

    print(intel)
