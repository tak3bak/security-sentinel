import os
import json
import stripe
from typing import Dict, Any

from nomadik_stripe_config import STRIPE_PRODUCTS

stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

PLAN_PRICES: Dict[str, str] = {
    "sentinel_core": os.getenv("STRIPE_PRICE_CORE", STRIPE_PRODUCTS["sentinel_core"]["price_id"]),
    "sentinel_compliance": os.getenv("STRIPE_PRICE_COMPLIANCE", STRIPE_PRODUCTS["sentinel_compliance"]["price_id"]),
    "sentinel_active_defense": os.getenv("STRIPE_PRICE_ACTIVE_DEFENSE", STRIPE_PRODUCTS["sentinel_active_defense"]["price_id"]),
    "sentinel_enterprise": os.getenv("STRIPE_PRICE_ENTERPRISE", STRIPE_PRODUCTS["sentinel_enterprise"]["price_id"]),
}

PRICE_TO_PLAN: Dict[str, str] = {
    price_id: plan for plan, price_id in PLAN_PRICES.items()
}

PLAN_LIMITS: Dict[str, Dict[str, Any]] = {
    "sentinel_core": {
        "monthly_events": 2500,
        "monthly_scans": 250,
        "active_endpoints": 15,
        "osint_concurrency": 2,
        "ai_triage_enabled": False,
        "compliance_mapping": False,
        "growth_api_access": False,
    },
    "sentinel_compliance": {
        "monthly_events": 15000,
        "monthly_scans": 1500,
        "active_endpoints": 50,
        "osint_concurrency": 5,
        "ai_triage_enabled": True,
        "compliance_mapping": True,
        "growth_api_access": False,
    },
    "sentinel_active_defense": {
        "monthly_events": 50000,
        "monthly_scans": 5000,
        "active_endpoints": 150,
        "osint_concurrency": 10,
        "ai_triage_enabled": True,
        "compliance_mapping": True,
        "growth_api_access": True,
    },
    "sentinel_enterprise": {
        "monthly_events": 250000,
        "monthly_scans": 25000,
        "active_endpoints": 1000,
        "osint_concurrency": 25,
        "ai_triage_enabled": True,
        "compliance_mapping": True,
        "growth_api_access": True,
    },
    "unknown": {
        "monthly_scans": 0,
        "monthly_events": 50,
        "active_endpoints": 1,
        "osint_concurrency": 1,
        "ai_triage_enabled": False,
        "compliance_mapping": False,
        "growth_api_access": False,
    },
}


def price_to_plan(price_id: str) -> str:
    return PRICE_TO_PLAN.get(price_id, "unknown")


def get_plan_limits(plan_tier: str) -> Dict[str, Any]:
    return PLAN_LIMITS.get(plan_tier.lower(), PLAN_LIMITS["unknown"])


def _to_clean_dict(stripe_obj: Any) -> Dict[str, Any]:
    """Safely convert Stripe object or raw dictionary to standard Python dict."""
    if hasattr(stripe_obj, "to_dict"):
        return stripe_obj.to_dict()
    if hasattr(stripe_obj, "items"):
        return dict(stripe_obj.items())
    return dict(stripe_obj)


def verify_stripe_event(payload: bytes, signature: str) -> Dict[str, Any]:
    """Synchronous Stripe webhook signature verification matching main.py invocation."""
    if not signature:
        raise ValueError("Missing Stripe signature")

    if STRIPE_WEBHOOK_SECRET:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=signature,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    else:
        raw_text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
        data = json.loads(raw_text)
        event = stripe.Event.construct_from(data, stripe.api_key)

    return _to_clean_dict(event)


def create_checkout_session(
    plan: str,
    customer_email: str,
    company_name: str,
    success_url: str,
    cancel_url: str,
) -> Dict[str, Any]:
    price_id = PLAN_PRICES.get(plan, plan)
    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        customer_email=customer_email,
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={"plan": plan, "company_name": company_name},
    )
    return {
        "checkout_url": getattr(session, "url", session.get("url", "")),
        "session_id": getattr(session, "id", session.get("id", "")),
    }


def create_customer_portal_session(customer_id: str, return_url: str) -> Dict[str, Any]:
    portal_session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=return_url,
    )
    return {
        "portal_url": getattr(portal_session, "url", portal_session.get("url", ""))
    }


def handle_webhook_event(event: Dict[str, Any]) -> Dict[str, Any]:
    event_type = event.get("type", "")
    data_object = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        customer_email = data_object.get("customer_email") or data_object.get("customer_details", {}).get("email")
        return {
            "status": "completed",
            "email": customer_email,
            "customer_id": data_object.get("customer"),
            "subscription_id": data_object.get("subscription"),
            "type": event_type,
        }
    return {"status": "unhandled", "type": event_type}
