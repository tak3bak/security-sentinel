#!/usr/bin/env python3
import os
import sys
import sqlite3
import stripe
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Force load the .env file from the exact directory where this script lives
script_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(script_dir, ".env")

if os.path.exists(env_path):
    print(f"ℹ️ Found .env file at: {env_path}")
    load_dotenv(dotenv_path=env_path)
else:
    print(f"⚠️ Warning: No .env file detected at: {env_path}")
    load_dotenv()

# Initialize Flask App
app = Flask(__name__)

# Configure Stripe Keys from Environment Variables
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
DB_PATH = os.path.join(script_dir, "sentinel_leases.db")

if not STRIPE_SECRET_KEY:
    print("❌ Error: STRIPE_SECRET_KEY environment variable is missing.")
    print(f"👉 Please ensure your .env file exists at {env_path} and contains STRIPE_SECRET_KEY.")
    sys.exit(1)

stripe.api_key = STRIPE_SECRET_KEY

# Ensure SQLite database table is initialized
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS leases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_email TEXT UNIQUE,
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            tier TEXT,
            status TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# Helper function to update user tier permissions in sentinel_leases.db
def update_user_lease(email, customer_id, subscription_id, tier, status):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO leases (customer_email, stripe_customer_id, stripe_subscription_id, tier, status)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(customer_email) DO UPDATE SET
            stripe_customer_id = excluded.stripe_customer_id,
            stripe_subscription_id = excluded.stripe_subscription_id,
            tier = excluded.tier,
            status = excluded.status,
            updated_at = CURRENT_TIMESTAMP
    """, (email, customer_id, subscription_id, tier, status))
    conn.commit()
    conn.close()
    print(f"💾 Database Updated: {email} -> Tier: {tier} ({status})")

# Helper function to remove or suspend a lease
def revoke_user_lease(subscription_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE leases 
        SET status = 'canceled', tier = 'none', updated_at = CURRENT_TIMESTAMP 
        WHERE stripe_subscription_id = ?
    """, (subscription_id,))
    conn.commit()
    conn.close()
    print(f"🚫 Lease Revoked for Subscription ID: {subscription_id}")


# --- ROUTES ---

@app.route("/")
def index():
    return "Security Sentinel Billing API Gateway is active."


@app.route("/verify-license", methods=["POST"])
def verify_license():
    """
    Endpoint used by the local Security Sentinel agent (CLI) to verify if a user has access.
    Expects JSON: { "email": "user@example.com" }
    """
    data = request.get_json() or {}
    email = data.get("email")

    if not email:
        return jsonify({"valid": False, "error": "Missing email parameter"}), 400

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT tier, status FROM leases WHERE customer_email = ?", (email,))
        row = cursor.fetchone()
        conn.close()

        if row:
            tier, status = row[0], row[1]
            is_active = (status == "active")
            return jsonify({
                "valid": is_active,
                "email": email,
                "tier": tier,
                "status": status
            })
        else:
            # No lease record found
            return jsonify({
                "valid": False,
                "email": email,
                "tier": "none",
                "status": "inactive"
            })

    except Exception as e:
        return jsonify({"valid": False, "error": f"Database check failed: {str(e)}"}), 500


@app.route("/create-checkout-session", methods=["POST"])
def create_checkout():
    data = request.get_json() or {}
    price_id = data.get("price_id")
    email = data.get("email")

    if not price_id:
        return jsonify({"error": "Missing price_id"}), 400

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            customer_email=email,
            line_items=[{"price": price_id, "quantity": 1}],
            mode='subscription',
            success_url='https://nomadiksec.github.io/success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url='https://nomadiksec.github.io/cancel',
        )
        return jsonify({"checkout_url": session.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    event = None

    if STRIPE_WEBHOOK_SECRET:
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, STRIPE_WEBHOOK_SECRET
            )
        except ValueError:
            return "Invalid payload", 400
        except stripe.error.SignatureVerificationError:
            return "Invalid signature", 400
    else:
        try:
            event = stripe.Event.construct_from(
                request.get_json(), stripe.api_key
            )
        except ValueError:
            return "Invalid payload", 400

    event_type = event["type"]
    data_object = event["data"]["object"]

    if event_type == "checkout.session.completed":
        session = data_object.to_dict()
        customer_email = session.get("customer_details", {}).get("email")
        customer_id = session.get("customer")
        subscription_id = session.get("subscription")
        
        if not subscription_id:
            print("⚠️ Checkout completed, but subscription ID was missing.")
        else:
            try:
                subscription_raw = stripe.Subscription.retrieve(subscription_id)
                subscription = subscription_raw.to_dict()
                
                price_id = subscription['items']['data'][0]['price']['id']
                
                tier_mapping = {
                    "price_1TtvhCDyViH34HKwQ5bAlMj4": "Basic",
                    "price_1TtvjaDyViH34HKweRxYtkQm": "Standard",
                    "price_1TtvkUDyViH34HKwZ7z0K4tJ": "Premium"
                }
                tier = tier_mapping.get(price_id, "Unknown")
                status = subscription.get("status", "active")
                
                update_user_lease(customer_email, customer_id, subscription_id, tier, status)
                
            except Exception as e:
                print(f"❌ Failed to retrieve subscription information: {e}")

    elif event_type in ["customer.subscription.deleted", "customer.subscription.updated"]:
        subscription = data_object.to_dict()
        subscription_id = subscription.get("id")
        status = subscription.get("status")

        if status in ["canceled", "unpaid"]:
            revoke_user_lease(subscription_id)
        else:
            print(f"🔄 Subscription {subscription_id} updated to status: {status}")

    return jsonify({"status": "success"})


if __name__ == "__main__":
    init_db()
    print("🔥 Starting Flask Server on http://localhost:4242")
    app.run(port=4242, debug=False)
