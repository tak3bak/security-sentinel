#!/usr/bin/env bash
# Start Development Engine safely loading environment variables

# Load local .env if present
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

# Verify required keys are set
if [ -z "$STRIPE_SECRET_KEY" ]; then
  echo "⚠️  STRIPE_SECRET_KEY is not set. Please add it to your .env file."
fi

if [ -z "$STRIPE_WEBHOOK_SECRET" ]; then
  echo "⚠️  STRIPE_WEBHOOK_SECRET is not set. Please add it to your .env file."
fi

python3 api/billing_handler.py
