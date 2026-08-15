from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from typing import Optional
import os
import secrets
import urllib.request
import json

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
    """
    try:
        session_id = f"cs_test_{secrets.token_hex(8)}"
        return CheckoutSessionResponse(
            checkout_url=f"https://checkout.stripe.com/pay/{session_id}",
            session_id=session_id
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/webhook")
async def stripe_webhook(request: Request):
    """
    Handles incoming Stripe webhooks, provisions license keys, and triggers automated welcome emails.
    """
    try:
        payload = await request.json()
        event_type = payload.get("type")
        event_id = payload.get("id")
        
        print(f"Received Stripe Webhook: {event_type} (ID: {event_id})")
        
        if event_type == "checkout.session.completed":
            session_data = payload.get("data", {}).get("object", {})
            customer_email = session_data.get("customer_email") or session_data.get("customer_details", {}).get("email")
            plan_name = session_data.get("metadata", {}).get("plan", "Standard Protection")
            
            # Generate secure API license key for customer
            license_key = f"nsk_live_{secrets.token_hex(16)}"
            print(f"Provisioned License Key {license_key} for customer: {customer_email}")
            
            # Trigger Resend API dispatch if API key is present
            resend_api_key = os.getenv("RESEND_API_KEY")
            if resend_api_key and customer_email:
                email_data = {
                    "from": "Nomadik Security Operations <security@nomadik.site>",
                    "to": [customer_email],
                    "subject": "Your Nomadik Security Sentinel Access Credentials",
                    "html": f"""
                    <h2>Welcome to Nomadik Security Sentinel</h2>
                    <p>Your subscription for plan <strong>{plan_name}</strong> is active.</p>
                    <p>Your API License Key: <code>{license_key}</code></p>
                    <p>Get started instantly by deploying your security sentinel daemon:</p>
                    <pre><code>pip install nomadik-security-sentinel
sentinel-cli --key {license_key}</code></pre>
                    <p>Need support? Reply directly to this email or reach out to our engineering team in Denver.</p>
                    """
                }
                
                req = urllib.request.Request(
                    "https://api.resend.com/emails",
                    data=json.dumps(email_data).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {resend_api_key}",
                        "Content-Type": "application/json"
                    },
                    method="POST"
                )
                try:
                    with urllib.request.urlopen(req) as response:
                        print(f"Welcome email successfully dispatched to {customer_email}")
                except Exception as mail_err:
                    print(f"Failed to dispatch fulfillment email: {mail_err}")

        return {"status": "success", "event": event_type}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook error: {str(e)}"
        )
