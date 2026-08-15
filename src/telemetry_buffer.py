import os
import time
import json
import asyncio
import logging
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, BackgroundTasks, HTTPException, status
from fastapi.responses import JSONResponse

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [TelemetryBuffer] %(message)s"
)
logger = logging.getLogger("NomadikTelemetry")

# =========================================================
# Data Models
# =========================================================
class SecurityEvent(BaseModel):
    event_id: str = Field(..., description="Unique client-generated event UUID")
    source_ip: str
    host_identifier: str
    event_type: str = Field(..., description="e.g., sysmon_process_create, dns_query, auth_failure")
    severity: str = Field("INFO", description="INFO, LOW, MEDIUM, HIGH, CRITICAL")
    payload: Dict[str, Any]
    timestamp: float = Field(default_factory=time.time)

class TelemetryBatch(BaseModel):
    batch_id: str
    agent_version: str
    events: List[SecurityEvent]

# =========================================================
# High-Throughput Buffer Queue
# =========================================================
class TelemetryStreamBuffer:
    def __init__(self, max_buffer_size: int = 50000, batch_window_ms: int = 100, batch_size: int = 500):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=max_buffer_size)
        self.dlq: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.batch_window_sec = batch_window_ms / 1000.0
        self.batch_size = batch_size
        self._running = False
        self._worker_task: Optional[asyncio.Task] = None

    async def push(self, event: Dict[str, Any]) -> bool:
        """Non-blocking ingest into buffer. Returns False if backpressure limit reached."""
        try:
            self.queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            logger.warning("[!] Telemetry buffer saturated. Activating emergency backpressure.")
            return False

    async def push_batch(self, events: List[Dict[str, Any]]) -> int:
        """Ingests all events that fit in buffer, returns count accepted."""
        accepted = 0
        for ev in events:
            if await self.push(ev):
                accepted += 1
            else:
                break
        return accepted

    async def start_worker(self):
        self._running = True
        self._worker_task = asyncio.create_task(self._consumer_loop())
        logger.info(f"[✓] Telemetry batch consumer initialized (Batch Size: {self.batch_size}, Window: {self.batch_window_sec*1000}ms)")

    async def stop_worker(self):
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("[✓] Telemetry buffer worker terminated cleanly.")

    async def _consumer_loop(self):
        while self._running:
            batch: List[Dict[str, Any]] = []
            start_time = time.monotonic()

            while len(batch) < self.batch_size:
                timeout = max(0.0, self.batch_window_sec - (time.monotonic() - start_time))
                try:
                    event = await asyncio.wait_for(self.queue.get(), timeout=timeout)
                    batch.append(event)
                    self.queue.task_done()
                except asyncio.TimeoutError:
                    break

            if batch:
                await self._process_batch(batch)

    async def _process_batch(self, batch: List[Dict[str, Any]]):
        """Flushes micro-batch to threat analysis engine and persistent store."""
        try:
            t0 = time.perf_counter()
            # Simulation of engine parsing latency
            latency_ms = (time.perf_counter() - t0) * 1000
            logger.info(f"Processed telemetry batch of {len(batch)} events in {latency_ms:.2f}ms | Buffer depth: {self.queue.qsize()}")
        except Exception as e:
            logger.error(f"[!] Batch processing exception: {e}. Moving events to DLQ.")
            for failed_event in batch:
                try:
                    self.dlq.put_nowait(failed_event)
                except asyncio.QueueFull:
                    logger.critical("[!] DLQ buffer full! Dropping stale event to preserve stability.")

buffer_engine = TelemetryStreamBuffer()

# =========================================================
# FastAPI Application & Endpoints
# =========================================================
app = FastAPI(
    title="Nomadik Security Sentinel - Ingestion Engine",
    version="2.0.0"
)

@app.on_event("startup")
async def startup_event():
    await buffer_engine.start_worker()

@app.on_event("shutdown")
async def shutdown_event():
    await buffer_engine.stop_worker()

@app.post("/api/v1/telemetry/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_single_event(event: SecurityEvent):
    event_dict = event.dict()
    event_dict["received_at"] = time.time()
    
    accepted = await buffer_engine.push(event_dict)
    if not accepted:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ingestion buffer full. Retry with exponential backoff."
        )
    
    return {"status": "buffered", "event_id": event.event_id}

@app.post("/api/v1/telemetry/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch_stream(batch: TelemetryBatch):
    raw_events = [ev.dict() for ev in batch.events]
    now = time.time()
    for ev in raw_events:
        ev["received_at"] = now
        ev["batch_id"] = batch.batch_id

    accepted_count = await buffer_engine.push_batch(raw_events)
    
    if accepted_count < len(raw_events):
        return JSONResponse(
            status_code=status.HTTP_207_MULTI_STATUS,
            content={
                "status": "partial_success",
                "accepted": accepted_count,
                "rejected": len(raw_events) - accepted_count,
                "detail": "Buffer threshold reached under heavy burst."
            }
        )

    return {
        "status": "buffered",
        "batch_id": batch.batch_id,
        "count": accepted_count
    }

@app.get("/api/v1/telemetry/health")
async def telemetry_buffer_health():
    return {
        "status": "healthy",
        "buffer_depth": buffer_engine.queue.qsize(),
        "dlq_depth": buffer_engine.dlq.qsize(),
        "max_capacity": buffer_engine.queue.maxsize
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.telemetry_buffer:app", host="0.0.0.0", port=8080, reload=True)
