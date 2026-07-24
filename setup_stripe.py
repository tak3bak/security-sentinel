import os
import stripe
from dotenv import load_dotenv

load_dotenv()

# .strip() removes any accidental trailing \n or spaces from the key
raw_key = os.getenv("STRIPE_SECRET_KEY", "")
stripe.api_key = raw_key.strip() if raw_key else "sk_test_placeholder"

DOMAIN = os.getenv("APP_URL", "https://nomadik.site").strip()

PRODUCTS = [
    {
        "name": "Nomadik Security Operations - Starter",
        "description": "Essential endpoint security monitoring and threat detection.",
        "amount": 9900,
        "interval": "month",
        "metadata": {"tier": "starter"}
    },
    {
        "name": "Nomadik Security Operations - Professional",
        "description": "Advanced autonomous threat defense, custom rules, and compliance reporting.",
        "amount": 29900,
        "interval": "month",
        "metadata": {"tier": "pro"}
    }
]

def setup_stripe_products_and_links():
    print(f"Setting up Stripe products and payment links targeting: {DOMAIN}...")
    created_links = {}
    
    for prod_data in PRODUCTS:
        product = stripe.Product.create(
            name=prod_data["name"],
            description=prod_data["description"],
            metadata=prod_data["metadata"]
        )
        
        price = stripe.Price.create(
            product=product.id,
            unit_amount=prod_data["amount"],
            currency="usd",
            recurring={"interval": prod_data["interval"]}
        )
        
        payment_link = stripe.PaymentLink.create(
            line_items=[{"price": price.id, "quantity": 1}],
            after_completion={
                "type": "redirect",
                "redirect": {
                    "url": f"{DOMAIN}/success?session_id={{CHECKOUT_SESSION_ID}}"
                }
            }
        )
        
        created_links[prod_data["metadata"]["tier"]] = payment_link.url
        print(f"[{prod_data['metadata']['tier'].upper()}] Link: {payment_link.url}")

    return created_links

if __name__ == "__main__":
    setup_stripe_products_and_links()
