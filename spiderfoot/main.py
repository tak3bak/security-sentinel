# -*- coding: utf-8 -*-
from fastapi import FastAPI
import logging
from routers import recon

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

app = FastAPI(
    title="Security Sentinel API",
    version="1.0.0",
    description="Active-defense, compliance monitoring, and automated reconnaissance API."
)

# Include reconnaissance router
app.include_router(recon.router)

@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "healthy", "service": "security-sentinel-api"}
