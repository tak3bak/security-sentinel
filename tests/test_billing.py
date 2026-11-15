import unittest
from app.billing import price_to_plan, get_plan_limits, PLAN_PRICES


class TestBilling(unittest.TestCase):
    def test_unknown_price_is_unknown(self):
        self.assertEqual(price_to_plan("not-a-price"), "unknown")

    def test_four_canonical_tiers_resolve(self):
        expected = [
            ("price_1U0Tq5D5LVILsj0FT4LoDMPq", "sentinel_core"),
            ("price_1U0Tq6D5LVILsj0FzgyT0oM5", "sentinel_compliance"),
            ("price_1U3NqHD5LVILsj0FiKwIGYwU", "sentinel_active_defense"),
            ("price_1U2K4gD5LVILsj0F1S5QbgUI", "sentinel_enterprise"),
        ]
        for price_id, plan in expected:
            self.assertEqual(PLAN_PRICES[plan], price_id)
            self.assertEqual(price_to_plan(price_id), plan)

    def test_plan_limits_by_tier(self):
        self.assertEqual(get_plan_limits("sentinel_core")["active_endpoints"], 15)
        self.assertTrue(get_plan_limits("sentinel_compliance")["compliance_mapping"])
        self.assertTrue(get_plan_limits("sentinel_active_defense")["growth_api_access"])
        self.assertEqual(get_plan_limits("sentinel_enterprise")["active_endpoints"], 1000)


if __name__ == "__main__":
    unittest.main()
