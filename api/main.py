import os
import stripe
import resend
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

# Initialize API Keys (loaded from environment variables in production)
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
resend.api_key = os.getenv("RESEND_API_KEY")

app = FastAPI(title="Security Sentinel Commercial API")

class ScanRequest(BaseModel):
    email: str
    company_name: str

@app.post("/api/checkout")
async def create_checkout_session(tier: str):
    """
    Generates a Stripe Checkout session for the specified tier.
    Designed for usage-based metered billing to avoid arbitrary SaaS pricing.
    """
    if tier != "sentinel":
        raise HTTPException(status_code=400, detail="Invalid or custom tier requested")
        
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    # Maps to your metered usage price ID in Stripe
                    'price': os.getenv("STRIPE_PRICE_ID_SENTINEL"),
                },
            ],
            mode='subscription',
            success_url="https://nomadik.site/success",
            cancel_url="https://nomadik.site/pricing",
        )
        return {"checkout_url": checkout_session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/lead/scan")
async def request_free_scan(req: ScanRequest):
    """
    Handles the Free / Scan tier by dispatching an automated 
    onboarding sequence and notifying internal operations.
    """
    try:
        # Alert Nomadik Internal Operations
        resend.Emails.send({
            "from": "sentinel@nomadik.site",
            "to": "kalen.vandenbos@gmail.com",
            "subject": f"New Assessment Request: {req.company_name}",
            "html": f"<h2>New Lead Notification</h2><p>Company: {req.company_name}</p><p>Contact: {req.email}</p><p>Action: Initiate external infrastructure scan.</p>"
        })
        
        # Dispatch Customer Welcome Sequence
        resend.Emails.send({
            "from": "sentinel@nomadik.site",
            "to": req.email,
            "subject": "Your Security Sentinel Assessment",
            "html": "<p>We have received your assessment request. The Nomadik Security Operations team will initiate your infrastructure scan shortly and reach out with your detailed report.</p>"
        })
        return {"status": "success", "message": "Assessment request processed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "operational", "service": "Security Sentinel API"}
