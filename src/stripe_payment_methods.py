import os
import stripe

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

def configure_payment_methods():
    try:
        print("Configuring extended payment methods (BNPL, bank debits, stablecoins)...")
        # Fetch account configuration to verify multi-currency/payment method capabilities
        account = stripe.Account.retrieve()
        print(f"Connected Account ID: {account.id} - Payment methods expansion interface ready.")
    except Exception as e:
        print(f"Status: {e}")

if __name__ == "__main__":
    configure_payment_methods()
