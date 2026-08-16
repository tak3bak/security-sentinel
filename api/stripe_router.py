import os
import stripe
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr

router = APIRouter()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

PRICE_MAP = {
    "starter": os.getenv("STRIPE_STARTER_PRICE_ID", "price_1xxxxxxxxxxxx299"), # $299/mo
    "pro": os.getenv("STRIPE_PRO_PRICE_ID", "price_1xxxxxxxxxxxx799"),     # $799/mo
}

class CheckoutRequest(BaseModel):
    tier: str
    email: EmailStr
    organization: str
    infrastructure_scope: str

@router.post("/api/create-checkout-session")
async def create_checkout_session(payload: CheckoutRequest):
    price_id = PRICE_MAP.get(payload.tier.lower())
    if not price_id:
        raise HTTPException(status_code=400, detail="Invalid subscription tier")

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            customer_email=payload.email,
            line_items=[{
                "price": price_id,
                "quantity": 1,
            }],
            mode="subscription",
            success_url="https://nomadik.site/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url="https://nomadik.site/pricing?canceled=true",
            metadata={
                "organization": payload.organization,
                "infrastructure_scope": payload.infrastructure_scope,
                "tier": payload.tier,
            },
        )
        return {"url": checkout_session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/webhook/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        customer_email = session.get("customer_email") or session.get("customer_details", {}).get("email")
        metadata = session.get("metadata", {})
        tier = metadata.get("tier")
        org = metadata.get("organization")
        print(f"[PROVISIONING] Success for {customer_email} | Tier: {tier} | Org: {org}")

    return {"status": "success"}
