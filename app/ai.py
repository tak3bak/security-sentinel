import httpx
from .config import settings

SYSTEM_PROMPT = """You are Nomadik Security Sentinel's local defensive triage engine.
Analyze only the supplied security event. Do not invent facts.
Return concise JSON with severity, confidence, summary, indicators, likely_causes,
and recommended_actions. Never recommend destructive actions. State uncertainty."""

async def triage(event: dict) -> dict:
    s = settings()
    prompt = SYSTEM_PROMPT + "\nEVENT:\n" + str(event)
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                f"{s.ollama_url}/api/generate",
                json={"model": s.ollama_model, "prompt": prompt, "stream": False},
            )
            r.raise_for_status()
            return {"provider": "ollama", "model": s.ollama_model, "response": r.json().get("response", "")}
    except Exception as exc:
        return {"provider": "ollama", "status": "unavailable", "error": str(exc)}
