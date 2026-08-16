import asyncio
import logging
from .config import settings

log = logging.getLogger("sentinel-worker")

async def main():
    log.info("Sentinel async worker online")
    try:
        from redis.asyncio import Redis
        redis = Redis.from_url(settings().redis_url, decode_responses=True)
        while True:
            try:
                item = await redis.brpop("sentinel:jobs", timeout=5)
                if item:
                    log.info("received job: %s", item[:500])
            except Exception:
                await asyncio.sleep(2)
    except Exception as e:
        log.warning(f"Redis unavailable ({str(e)}). Worker idling...")
        while True:
            await asyncio.sleep(10)

if __name__ == "__main__":
    asyncio.run(main())
