# app/billing.py
import os
from typing import Optional

PLAN_LIMITS = {
    "core": {"monthly_scans": 100, "monthly_events": 10_000, "ai_triage": True},
    "pro": {"monthly_scans": 1_000, "monthly_events": 100_000, "ai_triage": True},
    "elite": {"monthly_scans": 10_000, "monthly_events": 1_000_000, "ai_triage": True},
    "starter": {"monthly_scans": 100, "monthly_events": 10_000, "ai_triage": True},
    "premium": {"monthly_scans": 10_000, "monthly_events": 1_000_000, "ai_triage": True},
    "unknown": {"monthly_scans": 0, "monthly_events": 0, "ai_triage": False},
}

class BillingSettings:
    stripe_price_core: str = os.getenv("STRIPE_PRICE_CORE", "price_core_placeholder")
    stripe_price_pro: str = os.getenv("STRIPE_PRICE_PRO", "price_pro_placeholder")
    stripe_price_elite: str = os.getenv("STRIPE_PRICE_ELITE", "price_elite_placeholder")
    stripe_price_starter: str = os.getenv("STRIPE_PRICE_CORE", "price_core_placeholder")
    stripe_price_premium: str = os.getenv("STRIPE_PRICE_ELITE", "price_elite_placeholder")

s = BillingSettings()

def get_price_id_for_plan(plan: str) -> str:
    normalized_plan = plan.lower().strip()
    mapping = {
        "core": s.stripe_price_core,
        "pro": s.stripe_price_pro,
        "elite": s.stripe_price_elite,
        "starter": s.stripe_price_starter,
        "premium": s.stripe_price_premium,
    }
    price_id = mapping.get(normalized_plan)
    if not price_id:
        raise ValueError(f"Invalid or unmapped subscription tier: '{plan}'.")
    return price_id

def price_to_plan(price_id: str) -> str:
    if not price_id:
        return "unknown"
    price_map = {
        s.stripe_price_core: "core",
        s.stripe_price_pro: "pro",
        s.stripe_price_elite: "elite",
        s.stripe_price_starter: "core",
        s.stripe_price_premium: "elite",
    }
    return price_map.get(price_id, "unknown")

def get_plan_limits(plan: str):
    normalized_plan = plan.lower().strip()
    return PLAN_LIMITS.get(normalized_plan, PLAN_LIMITS["unknown"])
