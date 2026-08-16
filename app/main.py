from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import uuid
import secrets
import hashlib
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from .config import settings
from .db import get_session
from .schemas import EventIn, ScanIn, TriageIn, CheckoutIn, CheckoutOut, PortalIn, PortalOut
from .security import require_api_key
from .ingest import read_verified_wazuh
from .ai import triage
from .osint import surface_scan
from .billing import (
    verify_stripe_event,
    price_to_plan,
    create_checkout_session,
    create_customer_portal_session,
    get_plan_limits
)

app = FastAPI(title="Nomadik Security Sentinel", version="1.2.0")

# 1. CORS Configuration
origins = [
    "https://nomadik.site",
    "https://www.nomadik.site",
    "http://localhost:10000",
    "http://127.0.0.1:10000",
    "http://0.0.0.0:10000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "stripe-signature"],
)

# 2. Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in settings().cors_origins.split(",") if x.strip()],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"status": "ok", "service": "nomadik-security-sentinel"}

@app.get("/dashboard/")
async def dashboard():
    return FileResponse("web/index.html")

# --- Commercial & Billing Endpoints ---

@app.post("/api/v1/billing/checkout", response_model=CheckoutOut)
async def checkout(body: CheckoutIn):
    try:
        session_data = create_checkout_session(
            plan=body.plan,
            customer_email=body.customer_email,
            company_name=body.company_name,
            success_url=body.success_url,
            cancel_url=body.cancel_url,
        )
        return session_data
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"Stripe Checkout creation failed: {str(e)}")

@app.post("/api/v1/billing/portal", response_model=PortalOut, dependencies=[Depends(require_api_key)])
async def customer_portal(body: PortalIn, db: AsyncSession = Depends(get_session)):
    row = (await db.execute(
        text("SELECT stripe_customer_id FROM tenants WHERE id = :id"),
        {"id": body.tenant_id}
    )).mappings().first()
    
    if not row or not row["stripe_customer_id"]:
        raise HTTPException(404, "Tenant not found or has no active Stripe customer record")
    
    try:
        portal_data = create_customer_portal_session(row["stripe_customer_id"], body.return_url)
        return portal_data
    except Exception as e:
        raise HTTPException(500, f"Portal creation failed: {str(e)}")

@app.post("/api/v1/billing/stripe")
@app.post("/api/v1/billing/webhook")
async def stripe_webhook(request: Request, db: AsyncSession = Depends(get_session)):
    payload = await request.body()
    signature = request.headers.get("stripe-signature")
    if not signature:
        raise HTTPException(400, "Missing Stripe signature")
    
    try:
        event = verify_stripe_event(payload, signature)
    except Exception as exc:
        raise HTTPException(400, f"Invalid Stripe webhook: {type(exc).__name__}")

    event_type = event["type"]

    # 1. Automated Tenant Onboarding & Key Provisioning
    if event_type == "checkout.session.completed":
        session_obj = event["data"]["object"]
        customer_id = session_obj.get("customer")
        customer_email = session_obj.get("customer_email") or session_obj.get("customer_details", {}).get("email")
        metadata = session_obj.get("metadata") or {}
        plan = metadata.get("plan", "starter")
        company_name = metadata.get("company_name", customer_email or "New Tenant")

        tenant_id = uuid.uuid4()
        raw_api_key = f"nss_live_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(raw_api_key.encode()).hexdigest()

        await db.execute(text("""
            INSERT INTO tenants (id, name, stripe_customer_id, plan, subscription_status, api_key_hash, raw_api_key_initial)
            VALUES (:id, :name, :stripe_customer_id, :plan, 'active', :api_key_hash, :raw_api_key_initial)
            ON CONFLICT (stripe_customer_id) DO UPDATE SET
                plan = EXCLUDED.plan,
                subscription_status = 'active',
                updated_at = NOW()
        """), {
            "id": tenant_id,
            "name": company_name,
            "stripe_customer_id": customer_id,
            "plan": plan,
            "api_key_hash": key_hash,
            "raw_api_key_initial": raw_api_key,
        })
        await db.commit()

    # 2. Subscription Lifecycle Sync
    elif event_type in {"customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"}:
        sub_obj = event["data"]["object"]
        customer_id = sub_obj.get("customer")
        status = sub_obj.get("status", "unknown")
        items = sub_obj.get("items", {}).get("data") or []
        price_id = (items[0].get("price") or {}).get("id", "") if items else ""
        plan = price_to_plan(price_id)

        await db.execute(text("""
            UPDATE tenants 
            SET subscription_status = :status, plan = :plan, updated_at = NOW()
            WHERE stripe_customer_id = :customer
        """), {
            "status": status,
            "plan": plan,
            "customer": customer_id
        })
        await db.commit()

    return {"received": True}

# --- Core SecOps, Quota Metering & Scanning ---

@app.post("/api/v1/events", dependencies=[Depends(require_api_key)])
async def create_event(body: EventIn, db: AsyncSession = Depends(get_session)):
    # Metering & Tenant Quota Validation
    if body.tenant_id:
        tenant = (await db.execute(
            text("SELECT plan, subscription_status, events_used_this_month FROM tenants WHERE id = :id"),
            {"id": body.tenant_id}
        )).mappings().first()

        if tenant:
            if tenant["subscription_status"] != "active":
                raise HTTPException(403, f"Tenant subscription is {tenant['subscription_status']}")
            limits = get_plan_limits(tenant["plan"])
            if tenant["events_used_this_month"] >= limits["monthly_events"]:
                raise HTTPException(429, f"Monthly event limit reached for plan '{tenant['plan']}' ({limits['monthly_events']})")

    event_id = uuid.uuid4()
    await db.execute(text("""
        INSERT INTO events (id, tenant_id, source, event_type, severity, title, payload)
        VALUES (:id, :tenant_id, :source, :event_type, :severity, :title, :payload)
    """), {
        "id": event_id,
        "tenant_id": body.tenant_id,
        "source": body.source,
        "event_type": body.event_type,
        "severity": body.severity,
        "title": body.title,
        "payload": body.payload
    })

    if body.tenant_id:
        await db.execute(
            text("UPDATE tenants SET events_used_this_month = events_used_this_month + 1 WHERE id = :id"),
            {"id": body.tenant_id}
        )

    await db.commit()
    return {"id": str(event_id), "status": "accepted"}

@app.post("/api/v1/scans", dependencies=[Depends(require_api_key)])
async def create_scan(body: ScanIn, db: AsyncSession = Depends(get_session)):
    # Metering & Scan Quota Validation
    if body.tenant_id:
        tenant = (await db.execute(
            text("SELECT plan, subscription_status, scans_used_this_month FROM tenants WHERE id = :id"),
            {"id": body.tenant_id}
        )).mappings().first()

        if tenant:
            if tenant["subscription_status"] != "active":
                raise HTTPException(403, f"Tenant subscription is {tenant['subscription_status']}")
            limits = get_plan_limits(tenant["plan"])
            if tenant["scans_used_this_month"] >= limits["monthly_scans"]:
                raise HTTPException(429, f"Monthly scan limit reached for plan '{tenant['plan']}' ({limits['monthly_scans']})")

    scan_id = uuid.uuid4()
    result = await surface_scan(body.target)
    await db.execute(text("""
        INSERT INTO scans (id, tenant_id, target, scan_type, status, result, finished_at)
        VALUES (:id, :tenant_id, :target, :scan_type, 'complete', :result, :finished_at)
    """), {
        "id": scan_id,
        "tenant_id": body.tenant_id,
        "target": body.target,
        "scan_type": body.scan_type,
        "result": result,
        "finished_at": datetime.now(timezone.utc)
    })

    if body.tenant_id:
        await db.execute(
            text("UPDATE tenants SET scans_used_this_month = scans_used_this_month + 1 WHERE id = :id"),
            {"id": body.tenant_id}
        )

    await db.commit()
    return {"id": str(scan_id), "status": "complete", "result": result}

@app.post("/api/v1/ingest/wazuh")
async def wazuh_ingest(request: Request, db: AsyncSession = Depends(get_session)):
    payload = await read_verified_wazuh(request)
    rule = payload.get("rule") or {}
    try:
        level = int(rule.get("level", 0) or 0)
    except (TypeError, ValueError):
        level = 0
    severity = "critical" if level >= 14 else "high" if level >= 10 else "medium" if level >= 7 else "low"
    return await create_event(EventIn(
        source="wazuh",
        event_type=str(rule.get("id", "wazuh.alert")),
        severity=severity,
        title=str(rule.get("description", "Wazuh alert")),
        payload=payload
    ), db)

@app.post("/api/v1/triage", dependencies=[Depends(require_api_key)])
async def triage_event(body: TriageIn):
    return await triage(body.event)

@app.get("/api/v1/events", dependencies=[Depends(require_api_key)])
async def list_events(limit: int = 50, db: AsyncSession = Depends(get_session)):
    limit = max(1, min(limit, 200))
    rows = (await db.execute(
        text("SELECT id, source, event_type, severity, title, created_at FROM events ORDER BY created_at DESC LIMIT :limit"),
        {"limit": limit}
    )).mappings().all()
    return [dict(r) for r in rows]

@app.get("/api/v1/status", dependencies=[Depends(require_api_key)])
async def status(db: AsyncSession = Depends(get_session)):
    row = (await db.execute(text("""
        SELECT
            (SELECT count(*) FROM events) AS events,
            (SELECT count(*) FROM scans) AS scans,
            (SELECT count(*) FROM tenants) AS tenants
    """))).mappings().one()
    return dict(row)
