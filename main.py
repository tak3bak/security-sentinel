#!/usr/bin/env python3
"""
Nomadik Security Sentinel - Analysis Engine API
"""

import os
import json
import logging
import asyncio
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional, AsyncGenerator

from fastapi import FastAPI, Depends, Header, HTTPException, BackgroundTasks, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, DateTime, Text

# Logging Setup with Permission Fallback for Containerized Environments
LOG_DIR = "/var/log/nomadik_sentinel"
LOG_FILE = os.path.join(LOG_DIR, "packet_telemetry.log")

try:
    os.makedirs(LOG_DIR, exist_ok=True)
    # Test write permissions
    with open(LOG_FILE, "a"):
        pass
except (PermissionError, OSError):
    LOG_DIR = "./logs"
    os.makedirs(LOG_DIR, exist_ok=True)
    LOG_FILE = os.path.join(LOG_DIR, "packet_telemetry.log")

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("sentinel")

# Database Configuration
RAW_DB_URL = os.getenv("DATABASE_URL", "postgresql://sentinel_admin:secure_password@sentinel-db:5432/sentinel")
if RAW_DB_URL.startswith("postgresql://"):
    ASYNC_DB_URL = RAW_DB_URL.replace("postgresql://", "postgresql+asyncpg://")
else:
    ASYNC_DB_URL = RAW_DB_URL

engine = create_async_engine(ASYNC_DB_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

# Global set of active SSE subscribers
event_subscribers: set[asyncio.Queue] = set()

# SQLAlchemy Models
class Base(DeclarativeBase):
    pass

class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str] = mapped_column(String(45))
    source_port: Mapped[int] = mapped_column(Integer)
    destination_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(20))
    packet_length: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(50), default="packet_capture")
    info: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

# Telemetry Persistence & Broadcaster Helper
async def record_telemetry_event(event_data: dict):
    # 1. Log to disk for Wazuh
    try:
        log_entry = json.dumps(event_data)
        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        logger.error(f"Failed to write disk log: {e}")

    # 2. Write to PostgreSQL DB
    try:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                db_event = TelemetryEvent(
                    source_ip=event_data.get("source_ip", "Unknown"),
                    destination_ip=event_data.get("destination_ip", "Unknown"),
                    source_port=int(event_data.get("source_port", 0)),
                    destination_port=int(event_data.get("destination_port", 0)),
                    protocol=event_data.get("protocol", "Unknown"),
                    packet_length=int(event_data.get("packet_length", 0)),
                    event_type=event_data.get("event_type", "packet_capture"),
                    info=event_data.get("info", "")
                )
                session.add(db_event)
    except Exception as e:
        logger.error(f"Failed to write DB log: {e}")

    # 3. Broadcast to all active SSE streaming queues
    for q in list(event_subscribers):
        try:
            await q.put(event_data)
        except Exception:
            pass

# Application Lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("[*] Creating database tables if missing...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("[*] Nomadik Security Sentinel Engine Ready.")
    yield
    await engine.dispose()

app = FastAPI(
    title="Nomadik Security Sentinel Analysis Engine",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration
ALLOWED_ORIGINS = [
    "https://nomadik.site",
    "https://www.nomadik.site",
    "http://localhost:3000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication Dependency
SENTINEL_API_KEY = os.getenv("SENTINEL_API_KEY", "default-secret-change-me")

async def verify_api_key(x_api_key: Optional[str] = Header(None), background_tasks: BackgroundTasks = None):
    if not x_api_key or x_api_key != SENTINEL_API_KEY:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "127.0.0.1",
            "destination_ip": "127.0.0.1",
            "source_port": 0,
            "destination_port": 8000,
            "protocol": "HTTP",
            "packet_length": 0,
            "event_type": "auth_failure",
            "info": "Unauthorized API attempt"
        }
        if background_tasks:
            background_tasks.add_task(record_telemetry_event, event)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return x_api_key

# Endpoints
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "Nomadik Security Sentinel"}

@app.get("/api/v1/sentinel/status")
async def get_sentinel_status(
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "127.0.0.1",
        "destination_ip": "127.0.0.1",
        "source_port": 0,
        "destination_port": 8000,
        "protocol": "HTTP",
        "packet_length": 0,
        "event_type": "status_check",
        "info": "Authenticated status query"
    }
    background_tasks.add_task(record_telemetry_event, event)
    return {
        "status": "active",
        "packet_monitor": "running",
        "database": "postgresql_async_active",
        "security": "authenticated"
    }

# SSE Telemetry Generator
async def telemetry_event_generator(request: Request) -> AsyncGenerator[dict, None]:
    queue = asyncio.Queue()
    event_subscribers.add(queue)
    try:
        # Send initial connected ping
        yield {
            "event": "connected",
            "data": json.dumps({"status": "connected", "timestamp": datetime.now(timezone.utc).isoformat()})
        }
        while True:
            if await request.is_disconnected():
                break
            try:
                # Wait for next telemetry event with a 15-second heartbeat timeout
                event_data = await asyncio.wait_for(queue.get(), timeout=15.0)
                yield {
                    "event": "telemetry",
                    "data": json.dumps(event_data)
                }
            except asyncio.TimeoutError:
                yield {
                    "event": "ping",
                    "data": json.dumps({"heartbeat": datetime.now(timezone.utc).isoformat()})
                }
    finally:
        event_subscribers.remove(queue)

@app.get("/api/v1/sentinel/stream")
async def stream_telemetry(request: Request):
    return EventSourceResponse(telemetry_event_generator(request))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
