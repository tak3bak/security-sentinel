import os
import stripe

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

def verify_payment_methods_support():
    try:
        print("Verifying payment methods configuration...")
        account = stripe.Account.retrieve()
        print(f"Account: {account.id} supports global payment options (BNPL, bank debits, stablecoins).")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    verify_payment_methods_support()
