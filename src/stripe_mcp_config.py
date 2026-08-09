# Configuration template for integrating the Stripe MCP server
# to give AI agents access to the latest Stripe API features and docs.

MCP_CONFIG = {
    "mcpServers": {
        "stripe": {
            "command": "npx",
            "args": ["-y", "@stripe/mcp"],
            "env": {"STRIPE_SECRET_KEY": "YOUR_STRIPE_SECRET_KEY"},
        }
    }
}

print("Stripe MCP Server configuration defined.")
