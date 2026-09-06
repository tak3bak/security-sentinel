import os
from unittest.mock import patch, MagicMock
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from security_sentinel.billing_handler import router, stripe_webhook

app = FastAPI()
app.include_router(router)
client = TestClient(app)

def test_create_checkout_session_endpoint():
    response = client.post(
        "/api/v1/billing/checkout-session",
        json={
            "plan": "Pro",
            "customer_email": "test@nomadik.site",
            "company_name": "Nomadik Security Operations",
            "success_url": "https://nomadik.site/success",
            "cancel_url": "https://nomadik.site/cancel"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "checkout_url" in data
    assert "session_id" in data

def test_create_checkout_endpoint():
    response = client.post(
        "/api/v1/billing/checkout",
        json={
            "plan": "Enterprise",
            "customer_email": "test@nomadik.site"
        }
    )
    assert response.status_code == 200

def test_create_checkout_session_exception():
    with patch("security_sentinel.billing_handler.secrets.token_hex", side_effect=Exception("Token error")):
        response = client.post(
            "/api/v1/billing/checkout-session",
            json={
                "plan": "Pro",
                "customer_email": "test@nomadik.site"
            }
        )
        assert response.status_code == 500

def test_stripe_webhook_checkout_completed_with_resend(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "re_test_123")
    
    webhook_payload = {
        "type": "checkout.session.completed",
        "id": "evt_test_123",
        "data": {
            "object": {
                "customer_email": "client@nomadik.site",
                "metadata": {"plan": "Active Defense"}
            }
        }
    }
    
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response
        
        response = client.post("/api/v1/billing/webhook", json=webhook_payload)
        assert response.status_code == 200
        assert response.json() == {"status": "success", "event": "checkout.session.completed"}

def test_stripe_webhook_resend_failure(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "re_test_123")
    
    webhook_payload = {
        "type": "checkout.session.completed",
        "id": "evt_test_mail_fail",
        "data": {
            "object": {
                "customer_email": "client@nomadik.site",
                "metadata": {"plan": "Active Defense"}
            }
        }
    }
    
    with patch("urllib.request.urlopen", side_effect=Exception("Mail server down")):
        response = client.post("/api/v1/billing/webhook", json=webhook_payload)
        assert response.status_code == 200

def test_stripe_webhook_customer_details_fallback(monkeypatch):
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    
    webhook_payload = {
        "type": "checkout.session.completed",
        "id": "evt_test_456",
        "data": {
            "object": {
                "customer_details": {"email": "fallback@nomadik.site"},
                "metadata": {}
            }
        }
    }
    
    response = client.post("/api/v1/billing/webhook", json=webhook_payload)
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_stripe_webhook_outer_exception():
    mock_request = MagicMock(spec=Request)
    mock_request.json.side_effect = Exception("JSON parse error")
    
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await stripe_webhook(mock_request)
    assert exc_info.value.status_code == 400
