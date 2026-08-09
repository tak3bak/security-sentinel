import os
import stripe

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")


def create_embedded_checkout_session():
    try:
        print(
            "Configuring custom embedded payment flow components with embedded_page..."
        )
        session = stripe.checkout.Session.create(
            ui_mode="embedded_page",
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {"name": "Nomadik Security Sentinel Tier"},
                        "unit_amount": 4900,
                    },
                    "quantity": 1,
                }
            ],
            mode="payment",
            return_url="https://nomadik.site/return?session_id={CHECKOUT_SESSION_ID}",
        )
        print(f"Embedded Payment Session Client Secret Generated Successfully.")
        return session.client_secret
    except Exception as e:
        print(f"Error creating embedded session: {e}")


if __name__ == "__main__":
    create_embedded_checkout_session()
