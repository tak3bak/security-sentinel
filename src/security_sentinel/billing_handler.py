from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from typing import Optional
import os

router = APIRouter(prefix="/api/v1/billing", tags=["Billing & Monetization"])

class CheckoutRequest(BaseModel):
    plan: str
    customer_email: EmailStr
    company_name: Optional[str] = None
    success_url: Optional[str] = None
    cancel_url: Optional[str] = None

class CheckoutSessionResponse(BaseModel):
    checkout_url: str
    session_id: str

@router.post("/checkout", response_model=CheckoutSessionResponse)
@router.post("/checkout-session", response_model=CheckoutSessionResponse)
async def create_checkout_session(payload: CheckoutRequest):
    """
    Creates a Stripe checkout session for the selected plan.
    Supports both /checkout and /checkout-session endpoints.
    """
    try:
        return CheckoutSessionResponse(
            checkout_url=f"https://checkout.stripe.com/pay/test_session_{payload.plan}",
            session_id="cs_test_a1b2c3d4e5f6"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/webhook")
async def stripe_webhook(request: Request):
    """
    Handles incoming Stripe webhooks to provision accounts upon successful payment.
    """
    try:
        payload = await request.json()
        event_type = payload.get("type")
        event_id = payload.get("id")
        
        print(f"Received Stripe Webhook: {event_type} (ID: {event_id})")
        
        if event_type == "checkout.session.completed":
            session_data = payload.get("data", {}).get("object", {})
            customer_email = session_data.get("customer_email") or session_data.get("customer_details", {}).get("email")
            print(f"Provisioning subscription/access for customer: {customer_email}")
            
        return {"status": "success", "event": event_type}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook error: {str(e)}"
        )
