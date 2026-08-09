#!/usr/bin/env python3
import requests
import json

URL = "http://localhost:4242/create-checkout-session"

# Using your actual Basic Tier price ID from your Stripe list output!
YOUR_PRICE_ID = "price_1TtvhCDyViH34HKwQ5bAlMj4"
TEST_EMAIL = "nomadik_test@example.com"

payload = {"price_id": YOUR_PRICE_ID, "email": TEST_EMAIL}

headers = {"Content-Type": "application/json"}

try:
    print(f"📡 Sending checkout request for price: {YOUR_PRICE_ID}...")
    response = requests.post(URL, data=json.dumps(payload), headers=headers)

    if response.status_code == 200:
        data = response.json()
        print("\n✅ Checkout Session Created Successfully!")
        print("🔗 Open this URL in your web browser to complete the payment:")
        print("-" * 80)
        print(data.get("checkout_url"))
        print("-" * 80)
    else:
        print(f"❌ Failed to create checkout session: {response.status_code}")
        print(response.text)
except Exception as e:
    print(f"❌ Connection error: {e}")
