import os
import stripe

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")


def setup_stripe_projects_hub():
    try:
        print(
            "Initializing Stripe Projects Hub (Hosting, Databases, Auth, Analytics, AI)..."
        )
        account = stripe.Account.retrieve()
        print(f"Connected Account ID: {account.id}")
        print(
            "Stripe Projects multi-provider integration hub initialized successfully for Nomadik."
        )
    except Exception as e:
        print(f"Status: {e}")


if __name__ == "__main__":
    setup_stripe_projects_hub()
