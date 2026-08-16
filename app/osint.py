from urllib.parse import urlparse
import httpx
import dns.asyncresolver
from .config import settings

async def surface_scan(target: str) -> dict:
    target = target.strip()
    host = urlparse(target).hostname or target
    if len(host) > 253:
        raise ValueError("Target too long")
    result = {"target": target, "host": host, "dns": {}, "http": {}}
    try:
        answers = await dns.asyncresolver.resolve(host, "A")
        result["dns"]["addresses"] = list({a.to_text() for a in answers})
    except Exception as exc:
        result["dns"]["error"] = type(exc).__name__
    try:
        async with httpx.AsyncClient(
            timeout=settings().osint_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "Nomadik-Security-Sentinel/1.0"},
        ) as client:
            url = target if target.startswith(("http://", "https://")) else f"https://{host}"
            r = await client.get(url)
            result["http"] = {
                "status_code": r.status_code,
                "final_url": str(r.url),
                "server": r.headers.get("server"),
                "content_type": r.headers.get("content-type"),
                "security_headers": {
                    h: r.headers.get(h) for h in (
                        "strict-transport-security", "content-security-policy",
                        "x-content-type-options", "x-frame-options", "referrer-policy"
                    )
                },
            }
    except Exception as exc:
        result["http"]["error"] = type(exc).__name__
    return result
