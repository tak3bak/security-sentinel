import stripe
from .config import settings

PLAN_LIMITS = {
    "starter": {"monthly_scans": 100, "monthly_events": 10_000, "ai_triage": True},
    "pro": {"monthly_scans": 1_000, "monthly_events": 100_000, "ai_triage": True},
    "premium": {"monthly_scans": 10_000, "monthly_events": 1_000_000, "ai_triage": True},
    "unknown": {"monthly_scans": 0, "monthly_events": 0, "ai_triage": False},
}

def get_plan_limits(plan: str) -> dict:
    return PLAN_LIMITS.get(plan, PLAN_LIMITS["unknown"])

def get_price_id_for_plan(plan: str) -> str:
    s = settings()
    mapping = {
        "starter": s.stripe_price_starter,
        "pro": s.stripe_price_pro,
        "premium": s.stripe_price_premium,
    }
    price_id = mapping.get(plan)
    if not price_id:
        raise ValueError(f"Stripe Price ID not configured for plan tier: '{plan}'")
    return price_id

def create_checkout_session(plan: str, customer_email: str, company_name: str, success_url: str, cancel_url: str) -> dict:
    s = settings()
    if not s.stripe_secret_key:
        raise RuntimeError("STRIPE_SECRET_KEY is not configured")
    stripe.api_key = s.stripe_secret_key
    
    price_id = get_price_id_for_plan(plan)
    
    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        mode="subscription",
        customer_email=customer_email,
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={
            "plan": plan,
            "company_name": company_name,
            "customer_email": customer_email,
        },
        subscription_data={
            "metadata": {
                "plan": plan,
                "company_name": company_name,
            }
        }
    )
    return {"checkout_url": session.url, "session_id": session.id}

def create_customer_portal_session(stripe_customer_id: str, return_url: str) -> dict:
    s = settings()
    if not s.stripe_secret_key:
        raise RuntimeError("STRIPE_SECRET_KEY is not configured")
    stripe.api_key = s.stripe_secret_key
    
    portal_session = stripe.billing_portal.Session.create(
        customer=stripe_customer_id,
        return_url=return_url,
    )
    return {"portal_url": portal_session.url}

def verify_stripe_event(payload: bytes, signature: str):
    s = settings()
    if not s.stripe_webhook_secret:
        raise RuntimeError("STRIPE_WEBHOOK_SECRET is not configured")
    stripe.api_key = s.stripe_secret_key
    return stripe.Webhook.construct_event(payload, signature, s.stripe_webhook_secret)

def price_to_plan(price_id: str) -> str:
    s = settings()
    return {
        s.stripe_price_starter: "starter",
        s.stripe_price_pro: "pro",
        s.stripe_price_premium: "premium",
    }.get(price_id, "unknown")
