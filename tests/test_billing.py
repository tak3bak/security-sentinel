import unittest
from app.billing import price_to_plan


class TestBilling(unittest.TestCase):
    def test_unknown_price_is_unknown(self):
        self.assertEqual(price_to_plan("not-a-price"), "unknown")


if __name__ == "__main__":
    unittest.main()
