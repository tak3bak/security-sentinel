import ipaddress
from urllib.parse import urlparse
import httpx
import dns.asyncresolver
from .config import settings

def is_disallowed_ip(ip_str: str) -> bool:
    """Check if IP address is private, loopback, link-local, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return True

async def surface_scan(target: str) -> dict:
    target = target.strip()
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or target

    if not host or len(host) > 253:
        raise ValueError("Target hostname invalid or too long")

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid URL scheme: only HTTP and HTTPS are permitted")

    # Reject immediate direct IP targets that fall within private/reserved ranges
    try:
        direct_ip = ipaddress.ip_address(host)
        if is_disallowed_ip(str(direct_ip)):
            raise ValueError("Access to private or local network addresses is forbidden")
    except ValueError as exc:
        if "Access to private" in str(exc):
            raise

    result = {"target": target, "host": host, "dns": {}, "http": {}}
    resolved_ips = set()

    try:
        answers = await dns.asyncresolver.resolve(host, "A")
        resolved_ips = {a.to_text() for a in answers}
        result["dns"]["addresses"] = list(resolved_ips)
    except Exception as exc:
        result["dns"]["error"] = type(exc).__name__

    # SSRF guard: ensure resolved DNS addresses are not internal/private IPs
    for ip in resolved_ips:
        if is_disallowed_ip(ip):
            raise ValueError("Target resolves to a forbidden private or local IP address")

    try:
        async with httpx.AsyncClient(
            timeout=settings().osint_timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "Nomadik-Security-Sentinel/1.0"},
        ) as client:
            url = f"{parsed.scheme}://{host}"
            if parsed.port:
                url = f"{url}:{parsed.port}"
            if parsed.path:
                url = f"{url}{parsed.path}"
            if parsed.query:
                url = f"{url}?{parsed.query}"

            r = await client.get(url)
            result["http"] = {
                "status_code": r.status_code,
                "final_url": str(r.url),
                "server": r.headers.get("server"),
                "content_type": r.headers.get("content-type"),
                "security_headers": {
                    h: r.headers.get(h) for h in (
                        "strict-transport-security",
                        "content-security-policy",
                        "x-content-type-options",
                        "x-frame-options",
                        "referrer-policy",
                    )
                },
            }
    except Exception as exc:
        result["http"]["error"] = type(exc).__name__

    return result
