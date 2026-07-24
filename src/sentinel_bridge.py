import asyncio
import logging
import httpx
from datetime import datetime
# Import your existing audit writer
from audit_writer import log_security_event 

# Configuration
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL"
QUEUE = asyncio.Queue()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecuritySentinelBridge")

async def alert_worker():
    """Background worker to process alerts: Logs locally then notifies Discord."""
    async with httpx.AsyncClient() as client:
        while True:
            alert_data = await QUEUE.get()
            message = alert_data.get('content')
            
            # 1. Log to your audit_writer.py locally
            try:
                log_security_event(message)
                logger.info("Alert successfully written to local audit log.")
            except Exception as e:
                logger.error(f"Local audit write failed: {e}")

            # 2. Notify Discord
            try:
                response = await client.post(DISCORD_WEBHOOK_URL, json=alert_data, timeout=5.0)
                response.raise_for_status()
                logger.info(f"Alert successfully sent to Discord.")
            except Exception as e:
                logger.error(f"Discord notification failed: {e}")
            
            QUEUE.task_done()

async def add_to_alert_queue(message: str):
    """Adds a security finding to the queue."""
    alert_payload = {
        "content": f"🚨 **Security Sentinel Alert** | {datetime.now().isoformat()}\n{message}"
    }
    await QUEUE.put(alert_payload)
    logger.info("Alert queued for processing.")
