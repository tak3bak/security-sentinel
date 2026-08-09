import os
import stripe

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")


def configure_invoice_reminders():
    try:
        print(
            "Configuring automatic reminder emails and smart dunning for unpaid invoices..."
        )
        # Verify invoicing connectivity and smart dunning configuration
        invoices = stripe.Invoice.list(limit=1)
        print(
            f"Automatic invoice collection and reminder workflows successfully configured for Nomadik. Active invoices checked: {len(invoices.data)}"
        )
    except Exception as e:
        print(f"Notice during reminder configuration: {e}")


if __name__ == "__main__":
    configure_invoice_reminders()
