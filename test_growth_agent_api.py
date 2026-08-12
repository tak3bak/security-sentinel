#!/usr/bin/env python3
import sys
import os
import unittest
import logging

GROWTH_AGENT_DIR = os.path.expanduser("~/sentinel-growth-agent")
if os.path.exists(GROWTH_AGENT_DIR):
    sys.path.insert(0, GROWTH_AGENT_DIR)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class TestGrowthAgentAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = None
        try:
            import growth_agent_api
            from fastapi.testclient import TestClient
            cls.client = TestClient(growth_agent_api.app)
            logging.info("FastAPI TestClient initialized for Nomadik Sentinel Growth Agent API.")
        except Exception as e:
            logging.error(f"Failed to initialize FastAPI TestClient: {e}")

    def test_root_and_health_endpoints(self):
        """Test GET / and GET /health."""
        if not self.client:
            self.skipTest("FastAPI TestClient not available.")

        root_res = self.client.get("/")
        self.assertEqual(root_res.status_code, 200)
        self.assertEqual(root_res.json()["system"], "Nomadik Sentinel Growth Agent")

        health_res = self.client.get("/health")
        self.assertEqual(health_res.status_code, 200)
        self.assertEqual(health_res.json()["status"], "healthy")

    def test_ingest_lead_valid(self):
        """Test POST /api/v1/leads with a valid prospect payload."""
        if not self.client:
            self.skipTest("FastAPI TestClient not available.")

        payload = {
            "name": "Kalen Vandenbos",
            "company": "Nomadik Security Operations",
            "email": "test_lead@nomadik.site",
            "source": "automated_unit_test"
        }
        res = self.client.post("/api/v1/leads", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("lead_id", data)

    def test_ingest_lead_invalid_email(self):
        """Ensure invalid email inputs fail Pydantic validation (422 Unprocessable Entity)."""
        if not self.client:
            self.skipTest("FastAPI TestClient not available.")

        payload = {
            "name": "Invalid Lead",
            "company": "Bad Data Corp",
            "email": "not_an_email_address"
        }
        res = self.client.post("/leads", json=payload)
        self.assertEqual(res.status_code, 422)

    def test_billing_tiers_endpoint(self):
        """Test GET /billing/tiers returns expected Sentinel service packages."""
        if not self.client:
            self.skipTest("FastAPI TestClient not available.")

        res = self.client.get("/billing/tiers")
        self.assertEqual(res.status_code, 200)
        tiers = res.json().get("tiers", [])
        self.assertTrue(len(tiers) >= 2)
        tier_names = [t["name"] for t in tiers]
        self.assertIn("Sentinel Pro Active Defense", tier_names)

    def test_execute_task_endpoint(self):
        """Test POST /execute for generic action execution."""
        if not self.client:
            self.skipTest("FastAPI TestClient not available.")

        payload = {
            "action": "ping_sentinel",
            "target": "wazuh_agent_01"
        }
        res = self.client.post("/execute", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "executed")

if __name__ == "__main__":
    unittest.main(verbosity=2)
