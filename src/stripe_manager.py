import stripe
import os

# Bypass dotenv file loading entirely and set the clean key directly
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

def create_quick_payment_link(amount_cents: int = 4900, name: str = "Nomadik Security Sentinel Tier"):
    try:
        product = stripe.Product.create(name=name)
        price = stripe.Price.create(
            unit_amount=amount_cents,
            currency="usd",
            product=product.id,
        )
        payment_link = stripe.PaymentLink.create(
            line_items=[{"price": price.id, "quantity": 1}],
        )
        print(f"Payment Link Created Successfully: {payment_link.url}")
        return payment_link.url
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    create_quick_payment_link()
