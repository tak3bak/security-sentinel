#!/bin/bash
# Security Sentinel Billing Gateway
export STRIPE_SECRET_KEY="sk_test_51TsR7WDyViH34HKwiEnbxJ0eARzoy4jZvjay4OwzYE4m"
export STRIPE_WEBHOOK_SECRET="whsec_bd0ef25c01473bbf69a9749d60bb494243045c4a5184e1374c33e9eec6d3504d"

echo "[🚀 INITIALIZING] Launching Nomadik Billing Gateway..."
./.venv/bin/python3 billing_handler.py
