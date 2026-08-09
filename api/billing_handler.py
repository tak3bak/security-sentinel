import logging
from fastapi import APIRouter, HTTPException, Request

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/checkout")
async def create_checkout_session(request: Request):
    try:
        # Checkout logic
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Checkout error: {e}")
        raise HTTPException(status_code=500, detail="Internal processing error")

@router.post("/webhook")
async def stripe_webhook(request: Request):
    try:
        # Webhook logic
        return {"status": "received"}
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        raise HTTPException(status_code=400, detail="Invalid webhook payload")
