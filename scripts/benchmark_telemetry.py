#!/usr/bin/env python3
import json
import time
import uuid
import statistics
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET_URL = "http://127.0.0.1:8080/api/v1/telemetry/batch"
HEALTH_URL = "http://127.0.0.1:8080/api/v1/telemetry/health"
CONCURRENCY = 20
BATCHES_PER_WORKER = 25
EVENTS_PER_BATCH = 20
TOTAL_BATCHES = CONCURRENCY * BATCHES_PER_WORKER
TOTAL_EVENTS = TOTAL_BATCHES * EVENTS_PER_BATCH

EVENT_TEMPLATES = [
    {
        "event_type": "sysmon_process_create",
        "severity": "INFO",
        "payload": {"process": "mimikatz.exe", "command_line": "privilege::debug sekurlsa::logonpasswords"}
    },
    {
        "event_type": "sysmon_process_create",
        "severity": "INFO",
        "payload": {"process": "powershell.exe", "command_line": "-NoProfile -Exec Bypass -EncodedCommand W3N5c3RlbQ=="}
    },
    {
        "event_type": "dns_query",
        "severity": "INFO",
        "payload": {"query_domain": "c2.nomadik-defense.net", "record_type": "A"}
    },
    {
        "event_type": "auth_failure",
        "severity": "INFO",
        "payload": {"service": "sshd", "username": "root", "failed_attempts": 5}
    },
    {
        "event_type": "dns_query",
        "severity": "INFO",
        "payload": {"query_domain": "internal-db.nomadik.local", "record_type": "AAAA"}
    }
]

def generate_payload(worker_id: int, batch_idx: int) -> bytes:
    events = []
    for i in range(EVENTS_PER_BATCH):
        template = EVENT_TEMPLATES[(worker_id + batch_idx + i) % len(EVENT_TEMPLATES)]
        events.append({
            "event_id": str(uuid.uuid4()),
            "source_ip": f"10.0.{worker_id % 255}.{(batch_idx * 10 + i) % 250 + 1}",
            "host_identifier": f"sensor-node-{worker_id:02d}",
            "event_type": template["event_type"],
            "severity": template["severity"],
            "payload": template["payload"]
        })
    
    batch = {
        "batch_id": f"bench_{worker_id}_{batch_idx}_{uuid.uuid4().hex[:6]}",
        "agent_version": "v2.5.0-benchmark",
        "events": events
    }
    return json.dumps(batch).encode("utf-8")

def send_batch(worker_id: int, batch_idx: int) -> dict:
    data = generate_payload(worker_id, batch_idx)
    req = urllib.request.Request(
        TARGET_URL,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    
    t0 = time.perf_counter()
    status_code = 0
    success = False
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            status_code = resp.status
            success = status_code in (200, 202, 207)
    except urllib.error.HTTPError as e:
        status_code = e.code
    except Exception as e:
        status_code = 0

    latency_ms = (time.perf_counter() - t0) * 1000
    return {
        "status_code": status_code,
        "success": success,
        "latency_ms": latency_ms,
        "events_count": EVENTS_PER_BATCH
    }

def run_load_test():
    print("============================================================")
    print(" Nomadik Security Sentinel - High-Throughput Load Test")
    print("============================================================")
    print(f" Target Endpoint     : {TARGET_URL}")
    print(f" Concurrency Level   : {CONCURRENCY} workers")
    print(f" Batches per Worker  : {BATCHES_PER_WORKER}")
    print(f" Events per Batch    : {EVENTS_PER_BATCH}")
    print(f" Total Events Target : {TOTAL_EVENTS:,} events ({TOTAL_BATCHES} batches)")
    print("------------------------------------------------------------\n")

    latencies = []
    successful_batches = 0
    failed_batches = 0
    total_ingested_events = 0

    wall_start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = [
            executor.submit(send_batch, worker_id, batch_idx)
            for worker_id in range(CONCURRENCY)
            for batch_idx in range(BATCHES_PER_WORKER)
        ]

        for fut in as_completed(futures):
            res = fut.result()
            latencies.append(res["latency_ms"])
            if res["success"]:
                successful_batches += 1
                total_ingested_events += res["events_count"]
            else:
                failed_batches += 1

    wall_duration = time.perf_counter() - wall_start

    latencies.sort()
    avg_latency = statistics.mean(latencies) if latencies else 0
    p50_latency = statistics.median(latencies) if latencies else 0
    p95_latency = latencies[int(len(latencies) * 0.95)] if latencies else 0
    p99_latency = latencies[int(len(latencies) * 0.99)] if latencies else 0
    min_latency = min(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0

    events_per_second = total_ingested_events / wall_duration if wall_duration > 0 else 0
    batches_per_second = successful_batches / wall_duration if wall_duration > 0 else 0

    print("\n============================================================")
    print(" Benchmark Summary Results")
    print("============================================================")
    print(f" Wall Clock Time       : {wall_duration:.2f} seconds")
    print(f" Batches Succeeded     : {successful_batches}/{TOTAL_BATCHES} ({(successful_batches/TOTAL_BATCHES)*100:.1f}%)")
    print(f" Batches Failed        : {failed_batches}")
    print(f" Total Events Ingested : {total_ingested_events:,} events")
    print(f" Ingestion Throughput  : {events_per_second:,.2f} events/sec")
    print(f" Batch Throughput      : {batches_per_second:,.2f} batches/sec")
    print("------------------------------------------------------------")
    print(" Latency Percentiles (Round-Trip HTTP):")
    print(f"   Min Latency         : {min_latency:.2f} ms")
    print(f"   Avg Latency         : {avg_latency:.2f} ms")
    print(f"   p50 (Median)        : {p50_latency:.2f} ms")
    print(f"   p95                 : {p95_latency:.2f} ms")
    print(f"   p99                 : {p99_latency:.2f} ms")
    print(f"   Max Latency         : {max_latency:.2f} ms")
    print("============================================================\n")

if __name__ == "__main__":
    run_load_test()
