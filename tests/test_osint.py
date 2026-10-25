import unittest
from app.osint import surface_scan


class TestOsint(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_oversized_hostname(self):
        with self.assertRaises(ValueError):
            await surface_scan("a" * 254)


if __name__ == "__main__":
    unittest.main()
