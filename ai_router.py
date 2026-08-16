#!/usr/bin/env python3
import asyncio
import os
import sys
import httpx
from typing import Dict, Any, Optional

# Normalize Base URL (Handles '0.0.0.0:11434', 'localhost:11434', or 'http://...')
RAW_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
if not RAW_HOST.startswith("http://") and not RAW_HOST.startswith("https://"):
    OLLAMA_BASE_URL = f"http://{RAW_HOST}"
else:
    OLLAMA_BASE_URL = RAW_HOST

# Replace 0.0.0.0 with 127.0.0.1 for client connections
OLLAMA_BASE_URL = OLLAMA_BASE_URL.replace("0.0.0.0", "127.0.0.1")

TIER_1_MODEL = "qwen2.5-coder:1.5b"    # Fast triage (<15s on ARM)
TIER_2_MODEL = "qwen2.5-coder:latest"  # Deep AST audit / remediation

async def query_ollama(
    prompt: str,
    system_prompt: str = "You are a concise security engineering assistant. Provide direct, minimal technical output.",
    tier: int = 1,
    max_tokens: int = 256,
    num_ctx: Optional[int] = None,
    timeout_sec: float = 180.0
) -> Dict[str, Any]:
    """
    Executes tiered inference against Ollama with CPU thread optimization and strict timeout handling.
    """
    model = TIER_1_MODEL if tier == 1 else TIER_2_MODEL
    default_ctx = 2048 if tier == 1 else 4096
    
    # Optimize CPU threads for Android ARM big cores (typically 4 performance cores)
    cpu_cores = os.cpu_count() or 4
    num_threads = min(cpu_cores, 6)

    payload = {
        "model": model,
        "prompt": prompt,
        "system": system_prompt,
        "stream": False,
        "options": {
            "num_ctx": num_ctx or default_ctx,
            "num_predict": max_tokens,
            "num_thread": num_threads,
            "temperature": 0.1
        }
    }
    
    async with httpx.AsyncClient(timeout=timeout_sec) as client:
        try:
            url = f"{OLLAMA_BASE_URL}/api/generate"
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            
            total_duration_ns = data.get("total_duration", 0)
            duration_ms = round(total_duration_ns / 1_000_000, 2)
            eval_count = data.get("eval_count", 0)
            eval_duration_ns = data.get("eval_duration", 1)
            tps = round(eval_count / (eval_duration_ns / 1_000_000_000), 2) if eval_duration_ns > 0 else 0.0

            return {
                "success": True,
                "model": model,
                "response": data.get("response", "").strip(),
                "eval_tokens": eval_count,
                "duration_ms": duration_ms,
                "tokens_per_sec": tps
            }
        except httpx.HTTPStatusError as exc:
            return {
                "success": False,
                "model": model,
                "error": f"HTTP {exc.response.status_code}: {exc.response.text}"
            }
        except httpx.RequestError as exc:
            return {
                "success": False,
                "model": model,
                "error": f"Request failed to {OLLAMA_BASE_URL}: {type(exc).__name__} - {str(exc)}"
            }
        except Exception as exc:
            return {
                "success": False,
                "model": model,
                "error": f"Unexpected error: {str(exc)}"
            }

async def main():
    print(f"[INFO] Connecting to Ollama endpoint at: {OLLAMA_BASE_URL}")
    
    # 1. Test Tier 1 (1.5B)
    print("\n--- [Tier 1: 1.5B Fast Log Triage] ---")
    t1_res = await query_ollama(
        prompt="Classify this HTTP request: 'GET /index.php?id=1%20UNION%20SELECT%20null,password%20FROM%20users HTTP/1.1' 200",
        tier=1,
        max_tokens=128
    )
    if t1_res["success"]:
        print(f"[OK] Completed in {t1_res['duration_ms']}ms ({t1_res['tokens_per_sec']} tok/s):")
        print(t1_res["response"])
    else:
        print(f"[FAIL] Tier 1 Error: {t1_res['error']}")

    # 2. Test Tier 2 (7.6B) with capped generation length
    print("\n--- [Tier 2: 7.6B Deep Code Audit] ---")
    t2_res = await query_ollama(
        prompt="Audit this Python code snippet for command injection. Provide the 1-line safe fix:\n\nimport os\ndef ping(host):\n    os.system('ping -c 1 ' + host)",
        tier=2,
        max_tokens=160,
        timeout_sec=180.0
    )
    if t2_res["success"]:
        print(f"[OK] Completed in {t2_res['duration_ms']}ms ({t2_res['tokens_per_sec']} tok/s):")
        print(t2_res["response"])
    else:
        print(f"[FAIL] Tier 2 Error: {t2_res['error']}")

if __name__ == "__main__":
    asyncio.run(main())
