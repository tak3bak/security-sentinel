from typing import Any, Literal
from pydantic import BaseModel, Field, EmailStr

Severity = Literal["info", "low", "medium", "high", "critical"]
PlanTier = Literal["starter", "pro", "premium"]

class EventIn(BaseModel):
    tenant_id: str | None = None
    source: str = Field(min_length=1, max_length=64)
    event_type: str = Field(min_length=1, max_length=128)
    severity: Severity = "info"
    title: str = Field(min_length=1, max_length=500)
    payload: dict[str, Any] = Field(default_factory=dict)

class ScanIn(BaseModel):
    tenant_id: str | None = None
    target: str = Field(min_length=1, max_length=253)
    scan_type: Literal["surface", "dns", "http", "tls"] = "surface"

class TriageIn(BaseModel):
    event: dict[str, Any]

class CheckoutIn(BaseModel):
    plan: PlanTier
    customer_email: EmailStr
    company_name: str = Field(min_length=2, max_length=128)
    success_url: str = Field(default="https://nomadik.site/success?session_id={CHECKOUT_SESSION_ID}")
    cancel_url: str = Field(default="https://nomadik.site/pricing")

class CheckoutOut(BaseModel):
    checkout_url: str
    session_id: str

class PortalIn(BaseModel):
    tenant_id: str
    return_url: str = Field(default="https://nomadik.site/dashboard")

class PortalOut(BaseModel):
    portal_url: str
