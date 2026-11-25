import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request

TIER_1_MODEL = "qwen2.5-coder:1.5b"  # Fast triage (<15s on ARM)
TRIAGE_PREFERRED_MODELS = [
    "qwen2.5-coder-triage:7b",
    "qwen2.5-coder:1.5b",
    "qwen2.5-coder:7b",
    "llama3.2:1b",
]
DEFAULT_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")


def load_sentinel_jwt_secret() -> str:
    """Resolve SENTINEL_JWT_SECRET from env or ~/projects/security-sentinel/.env."""
    secret = os.environ.get("SENTINEL_JWT_SECRET", "").strip()
    if secret:
        return secret

    candidate_paths = [
        Path(__file__).resolve().parent / ".env",
        Path.home() / "projects" / "security-sentinel" / ".env",
    ]
    for env_path in candidate_paths:
        if not env_path.is_file():
            continue
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if line.startswith("SENTINEL_JWT_SECRET="):
                val = line.split("=", 1)[1].strip()
                if len(val) >= 2 and (
                    (val.startswith('"') and val.endswith('"'))
                    or (val.startswith("'") and val.endswith("'"))
                ):
                    val = val[1:-1]
                if val:
                    return val
    return ""


def get_installed_ollama_models(ollama_url: str = DEFAULT_OLLAMA_URL, timeout: float = 4.0) -> List[str]:
    """Query local Ollama /api/tags and return installed model names."""
    url = f"{ollama_url.rstrip('/')}/api/tags"
    try:
        with urllib_request.urlopen(url, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            return [m.get("name", "") for m in payload.get("models", []) if m.get("name")]
    except Exception:
        return []


def select_triage_model(
    requested_model: Optional[str] = None,
    ollama_url: str = DEFAULT_OLLAMA_URL,
) -> str:
    """Pick the best available local model for triage digest execution."""
    installed = get_installed_ollama_models(ollama_url=ollama_url)
    if requested_model:
        if not installed or requested_model in installed:
            return requested_model
    for candidate in TRIAGE_PREFERRED_MODELS:
        if candidate in installed:
            return candidate
    if installed:
        return installed[0]
    return requested_model or TIER_1_MODEL


def _heuristic_verdict(events: List[Dict[str, Any]]) -> Dict[str, str]:
    """Deterministic fallback classification for telemetry batches."""
    for ev in events:
        event_type = str(ev.get("event_type", "")).lower()
        attempts = int(ev.get("attempts") or 0)
        src_ip = str(ev.get("src_ip", ""))
        if "auth_failure" in event_type or "brute" in event_type or "stuffing" in event_type or attempts >= 10:
            return {
                "risk_level": "HIGH",
                "verdict": "QUARANTINE_CANDIDATE",
                "policy_action": "ISOLATE_AND_BLOCK_SOURCE",
                "rationale": f"Anomalous activity ({event_type or 'event'}, attempts={attempts}) from {src_ip or 'unknown'}.",
            }
    return {
        "risk_level": "LOW",
        "verdict": "AUTHORIZED_PASS",
        "policy_action": "ALLOW_WITH_LOGGING",
        "rationale": "Telemetry matches routine or low-risk operational activity.",
    }


def generate_triage_digest(
    source: str,
    events: List[Dict[str, Any]],
    model: Optional[str] = None,
    temperature: float = 0.0,
    ollama_url: str = DEFAULT_OLLAMA_URL,
    timeout: float = 35.0,
) -> Dict[str, Any]:
    """Run local Ollama triage inference at temperature=0.0 and return structured digest."""
    chosen_model = select_triage_model(requested_model=model, ollama_url=ollama_url)
    fallback = _heuristic_verdict(events)

    system_prompt = (
        "You are Nomadik Security Sentinel's SOC triage engine. "
        "Analyze security telemetry events and respond ONLY with a single JSON object containing keys: "
        '"risk_level" ("LOW"|"MEDIUM"|"HIGH"), '
        '"verdict" ("AUTHORIZED_PASS"|"MONITOR"|"QUARANTINE_CANDIDATE"), '
        '"policy_action" (string), and '
        '"summary" (concise 1-2 sentence triage summary).'
    )
    user_prompt = json.dumps(
        {
            "source": source,
            "event_count": len(events),
            "events": events,
        },
        separators=(",", ":"),
    )

    body = json.dumps(
        {
            "model": chosen_model,
            "stream": False,
            "options": {
                "temperature": float(temperature),
            },
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
    ).encode("utf-8")

    endpoint = f"{ollama_url.rstrip('/')}/api/chat"
    req = urllib_request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )

    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            raw_resp = json.loads(resp.read().decode("utf-8", errors="replace"))
            content = (
                raw_resp.get("message", {}).get("content", "")
                if isinstance(raw_resp, dict)
                else ""
            ).strip()

            parsed_json: Optional[Dict[str, Any]] = None
            if content:
                try:
                    parsed_json = json.loads(content)
                except json.JSONDecodeError:
                    start = content.find("{")
                    end = content.rfind("}")
                    if start != -1 and end != -1 and end > start:
                        try:
                            parsed_json = json.loads(content[start : end + 1])
                        except json.JSONDecodeError:
                            parsed_json = None

            if isinstance(parsed_json, dict):
                return {
                    "status": "ok",
                    "source": source,
                    "model_used": chosen_model,
                    "ollama_reachable": True,
                    "risk_level": str(parsed_json.get("risk_level") or fallback["risk_level"]).upper(),
                    "verdict": str(parsed_json.get("verdict") or fallback["verdict"]).upper(),
                    "policy_action": str(parsed_json.get("policy_action") or fallback["policy_action"]),
                    "summary": str(parsed_json.get("summary") or content or fallback["rationale"]),
                }

            return {
                "status": "ok",
                "source": source,
                "model_used": chosen_model,
                "ollama_reachable": True,
                "risk_level": fallback["risk_level"],
                "verdict": fallback["verdict"],
                "policy_action": fallback["policy_action"],
                "summary": content or fallback["rationale"],
            }

    except (urllib_error.URLError, urllib_error.HTTPError, TimeoutError, Exception) as exc:
        return {
            "status": "degraded",
            "source": source,
            "model_used": chosen_model,
            "ollama_reachable": False,
            "risk_level": fallback["risk_level"],
            "verdict": fallback["verdict"],
            "policy_action": fallback["policy_action"],
            "summary": fallback["rationale"],
            "ollama_error": str(exc),
        }
