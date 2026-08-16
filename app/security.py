import secrets
from fastapi import Header, HTTPException
from .config import settings

async def require_api_key(x_api_key: str | None = Header(default=None)):
    expected = settings().sentinel_api_key
    if not x_api_key or not expected or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid API key")
