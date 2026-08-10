import os
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from hybrid_crypto import HybridEncryption

# 1. Key Persistence Configuration
KEYS_DIR = os.path.expanduser("~/security-sentinel/keys")
PRIV_KEY_PATH = os.path.join(KEYS_DIR, "sentinel_private.pem")
PUB_KEY_PATH = os.path.join(KEYS_DIR, "sentinel_public.pem")


def ensure_keypair() -> tuple[bytes, bytes]:
    """Generates and persists RSA keypair if not already present."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    if not os.path.exists(PRIV_KEY_PATH) or not os.path.exists(PUB_KEY_PATH):
        priv_pem, pub_pem = HybridEncryption.generate_key_pair(bits=2048)
        with open(PRIV_KEY_PATH, "wb") as f:
            f.write(priv_pem)
        with open(PUB_KEY_PATH, "wb") as f:
            f.write(pub_pem)
        return priv_pem, pub_pem

    with open(PRIV_KEY_PATH, "rb") as f:
        priv_pem = f.read()
    with open(PUB_KEY_PATH, "rb") as f:
        pub_pem = f.read()
    return priv_pem, pub_pem


# Initialize Keypair & Decryption Engine
PRIV_PEM, PUB_PEM = ensure_keypair()
server_receiver = HybridEncryption(private_key_pem=PRIV_PEM)

app = FastAPI(title="Nomadik Security Sentinel Ingress")


# 2. Cryptographic Dependency Injection
async def decrypt_sentinel_payload(request: Request) -> bytes:
    """FastAPI dependency to validate and decrypt incoming GCM/RSA payloads."""
    try:
        body = await request.json()
        encrypted_payload = body.get("payload")
        context_aad = body.get("context", "").encode("utf-8") if body.get("context") else None

        if not encrypted_payload:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing 'payload' field."
            )

        # Unwraps RSA ephemeral key and checks AES-GCM MAC tag
        decrypted_bytes = server_receiver.decrypt(encrypted_payload, associated_data=context_aad)
        return decrypted_bytes

    except ValueError:
        # Uniform 400 error to eliminate timing/padding oracles
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload decryption or MAC verification failed."
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request structure."
        )


# 3. Secure Telemetry Endpoint
@app.post("/api/v1/telemetry")
async def receive_telemetry(raw_payload: bytes = Depends(decrypt_sentinel_payload)):
    """Protected route receiving authenticated, decrypted plaintext."""
    plaintext_data = raw_payload.decode("utf-8")
    return {
        "status": "success",
        "message": "Telemetry verified and ingested.",
        "received_bytes": len(raw_payload),
        "data": plaintext_data
    }


if __name__ == "__main__":
    import uvicorn
    print(f"[+] Loaded Private Key from: {PRIV_KEY_PATH}")
    print(f"[+] Loaded Public Key from: {PUB_KEY_PATH}")
    uvicorn.run(app, host="127.0.0.1", port=8000)
