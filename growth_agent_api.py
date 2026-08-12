import os
import stripe
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(
    title="Nomadik Growth Agent API",
    description="Automated Lead Tracking & Stripe Payment Webhook Processing Engine",
    version="1.0.0"
)

# Enable CORS for nomadik.site
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

stripe.api_key = os.getenv("STRIPE_API_KEY")
endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")

@app.get("/")
async def root():
    return {
        "status": "online",
        "system": "Nomadik Sentinel Growth Agent",
        "version": "1.0.0",
        "port": 8080,
        "payment_link": "https://buy.stripe.com/eVq28qeUm98ngRebr1d7q0a"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/webhook/stripe")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None)):
    payload = await request.body()
    
    if endpoint_secret and stripe_signature:
        try:
            event = stripe.Webhook.construct_event(
                payload, stripe_signature, endpoint_secret
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid payload")
        except stripe.error.SignatureVerificationError:
            raise HTTPException(status_code=400, detail="Invalid signature")
    else:
        # Fallback payload parsing if signature verification secret is not yet set
        import json
        try:
            event = json.loads(payload.decode("utf-8"))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = event.get("type")

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]
        customer_email = session.get("customer_details", {}).get("email") or session.get("customer_email")
        amount_total = (session.get("amount_total") or 0) / 100.0
        payment_status = session.get("payment_status")

        print(f"[+] Payment Successful: ${amount_total:.2f} USD from {customer_email} (Status: {payment_status})")
        
        # Log transaction locally
        with open("transactions.log", "a") as log:
            log.write(f"EMAIL: {customer_email} | AMOUNT: ${amount_total:.2f} | STATUS: {payment_status}\n")

    return {"status": "success", "event": event_type}

if __name__ == "__main__":
    uvicorn.run("growth_agent_api:app", host="0.0.0.0", port=8080, reload=False)
