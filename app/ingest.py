import hashlib
import hmac
import json
from fastapi import HTTPException, Request
from .config import settings

async def read_verified_wazuh(request: Request) -> dict:
    raw = await request.body()
    if len(raw) > settings().max_event_bytes:
        raise HTTPException(413, "Event too large")
    secret = settings().wazuh_shared_secret
    if secret:
        provided = request.headers.get("x-wazuh-signature", "")
        expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(provided, expected):
            raise HTTPException(401, "Invalid Wazuh signature")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON")
