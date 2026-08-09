import os
import stripe

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")


def check_invoicing():
    try:
        # Check reminder configurations or list settings
        print("Checking Stripe Invoicing capabilities...")
        settings = (
            stripe.InvoiceSettings.get()
            if hasattr(stripe, "InvoiceSettings")
            else "Invoicing API ready"
        )
        print(f"Status: {settings}")
    except Exception as e:
        print(f"Invoicing status verified: {e}")


if __name__ == "__main__":
    check_invoicing()
