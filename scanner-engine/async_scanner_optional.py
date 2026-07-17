"""
OPTIONAL performance upgrade - not wired into app.py by default.

app.py currently runs the 4 attack modules concurrently at the module
level (via asyncio.to_thread + asyncio.gather), which is fast enough
for a 4-endpoint demo target. This file shows how you'd go further and
parallelize INDIVIDUAL PAYLOADS within a single attack module using
aiohttp, if you ever scan a target with many more endpoints/payloads
and need real concurrency at that finer grain.

Left here as a documented extension point rather than wired in, because
aiohttp adds a second HTTP client dependency and more moving parts than
a hackathon demo needs by default - `requests` + asyncio.to_thread is
simpler to debug live on stage.
"""
import aiohttp
import asyncio


async def send_payload(session: aiohttp.ClientSession, url: str, method: str, data: dict, payload_id: str):
    start = asyncio.get_event_loop().time()
    try:
        async with session.request(
            method, url, data=data, timeout=aiohttp.ClientTimeout(total=8)
        ) as resp:
            body = await resp.text()
            elapsed = asyncio.get_event_loop().time() - start
            return {
                "payload_id": payload_id,
                "status": resp.status,
                "body": body,
                "elapsed": elapsed,
            }
    except Exception as e:
        return {"payload_id": payload_id, "error": str(e)}


async def run_attack_batch(attack_requests: list[dict]):
    """
    attack_requests: list of {"url":..., "method":..., "data":..., "id":...}
    Fires all requests concurrently instead of one at a time.
    """
    async with aiohttp.ClientSession() as session:
        tasks = [
            send_payload(session, req["url"], req["method"], req["data"], req["id"])
            for req in attack_requests
        ]
        return await asyncio.gather(*tasks)
