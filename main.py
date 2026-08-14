import os
from fastapi import FastAPI, Request, HTTPException, Header
import stripe
import resend

app = FastAPI(title="Nomadik Security Sentinel API", version="1.0.0")

# Initialize API Keys from Environment
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
ENDPOINT_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
resend.api_key = os.getenv("RESEND_API_KEY")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "nomadik-sentinel-api"}

@app.post("/webhook")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None)):
    """
    Stripe webhook endpoint with cryptographic signature verification,
    tier detection, and automated customer access dispatch.
    """
    payload = await request.body()

    if not stripe_signature:
        raise HTTPException(status_code=400, detail="Missing stripe-signature header")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=stripe_signature,
            secret=ENDPOINT_SECRET
        )
    except ValueError as e:
        print(f"⚠️ Invalid payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        print(f"⚠️ Webhook signature verification failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event.get("type")
    event_data = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        metadata = event_data.get("metadata", {})
        tier = metadata.get("tier", "standard")
        
        customer_details = event_data.get("customer_details", {})
        customer_email = customer_details.get("email") or event_data.get("customer_email")
        customer_name = customer_details.get("name", "Valued Customer")

        print(f"✅ Successful checkout: Tier [{tier}] for Customer [{customer_email}]")

        if customer_email:
            try:
                resend.Emails.send({
                    "from": "Nomadik Security Operations <support@nomadiksystems.com>",
                    "to": [customer_email],
                    "subject": f"Your Nomadik Security Sentinel Access ({tier.upper()})",
                    "html": f"""
                      <h2>Welcome to Nomadik Systems, {customer_name}!</h2>
                      <p>Your payment for the <strong>{tier.upper()}</strong> tier has been successfully processed.</p>
                      <p>You can access your deployment portal and instructions here: <a href="https://nomadiksystems.com/portal">Nomadik Portal</a></p>
                      <br>
                      <p>Stay secure,<br><strong>Nomadik Security Operations</strong></p>
                    """
                })
                print(f"📧 Access email successfully dispatched to {customer_email}")
            except Exception as email_error:
                print(f"❌ Failed to dispatch access email: {email_error}")

    elif event_type == "payment_intent.payment_failed":
        payment_intent_id = event_data.get("id")
        print(f"❌ Payment failed for intent: {payment_intent_id}")

    else:
        print(f"ℹ️ Unhandled event type: {event_type}")

    return {"received": True}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 10000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
