import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ai_router import generate_triage_digest, load_sentinel_jwt_secret  # noqa: E402

try:
    from security_sentinel.billing_handler import router as billing_router  # noqa: E402
except Exception:
    billing_router = None

app = FastAPI(title="Nomadik Security Sentinel API", version="1.0.0")
security_scheme = HTTPBearer(auto_error=False)

if billing_router is not None:
    app.include_router(billing_router)


class TelemetryEvent(BaseModel):
    timestamp: Optional[int] = None
    src_ip: Optional[str] = None
    event_type: str = "telemetry_event"
    service: Optional[str] = None
    attempts: int = 1
    summary: str = ""


class TriageDigestRequest(BaseModel):
    source: str = Field(default="sentinel-agent", min_length=1)
    model: Optional[str] = None
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    events: List[Dict[str, Any]] = Field(default_factory=list)


def verify_sentinel_jwt(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> Dict[str, Any]:
    """Validate Bearer token using HS256 and SENTINEL_JWT_SECRET."""
    secret = load_sentinel_jwt_secret()
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SENTINEL_JWT_SECRET is not configured",
        )

    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials.strip()
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
        if not isinstance(claims, dict):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid JWT claims payload",
            )
        return claims
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT token has expired",
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid JWT token: {exc}",
        ) from exc


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "nomadik-security-sentinel",
        "jwt_secret_configured": bool(load_sentinel_jwt_secret()),
        "ollama_url": os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"),
    }


@app.post("/api/v1/triage/digest")
async def triage_digest(
    payload: TriageDigestRequest,
    request: Request,
    claims: Dict[str, Any] = Depends(verify_sentinel_jwt),
) -> Dict[str, Any]:
    """Authenticate via HS256 JWT and generate a SOC triage digest backed by local Ollama."""
    if not payload.events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="events list must not be empty",
        )

    result = generate_triage_digest(
        source=payload.source,
        events=payload.events,
        model=payload.model,
        temperature=payload.temperature,
    )
    result["subject"] = claims.get("sub", "unknown")
    result["client_host"] = request.client.host if request.client else "unknown"
    return result
