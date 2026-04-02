# engine/rate_limiter.py
import asyncio

async def throttle(delay: float = 0.05):
    await asyncio.sleep(delay)
