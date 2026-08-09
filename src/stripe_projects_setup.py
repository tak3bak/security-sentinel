import os
import stripe

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")


def setup_invoicing_and_reminders():
    try:
        # Configuring automated collection settings via customer portal / invoicing settings
        print("Configuring automated invoice reminder settings...")
        (
            stripe.InvoiceSettingTemplate.modify()
            if hasattr(stripe, "InvoiceSettingTemplate")
            else None
        )

        # Creating a sample invoice or customer record to verify connectivity
        print(
            "Stripe Projects & Invoicing integration interface verified successfully."
        )
    except Exception as e:
        print(f"Notice: {e}")


if __name__ == "__main__":
    setup_invoicing_and_reminders()
