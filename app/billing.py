import os
import json
import stripe
from typing import Optional, Dict, Any

stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

PRICE_TO_PLAN = {
    os.getenv("STRIPE_PRICE_STARTER", "price_starter"): "starter",
    os.getenv("STRIPE_PRICE_PRO", "price_pro"): "pro",
    os.getenv("STRIPE_PRICE_PREMIUM", "price_premium"): "premium",
}

PLAN_PRICES = {
    "starter": os.getenv("STRIPE_PRICE_STARTER", "price_starter"),
    "pro": os.getenv("STRIPE_PRICE_PRO", "price_pro"),
    "premium": os.getenv("STRIPE_PRICE_PREMIUM", "price_premium"),
}

PLAN_LIMITS = {
    "starter": {
        "monthly_events": 500,
        "monthly_scans": 100,
        "active_endpoints": 3,
        "osint_concurrency": 1,
        "ai_triage_enabled": False,
    },
    "pro": {
        "monthly_events": 5000,
        "monthly_scans": 1000,
        "active_endpoints": 15,
        "osint_concurrency": 5,
        "ai_triage_enabled": True,
    },
    "premium": {
        "monthly_events": 100000,
        "monthly_scans": 10000,
        "active_endpoints": 100,
        "osint_concurrency": 20,
        "ai_triage_enabled": True,
    },
    "unknown": {
        "monthly_scans": 0,
        "monthly_events": 50,
        "active_endpoints": 1,
        "osint_concurrency": 1,
        "ai_triage_enabled": False,
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
