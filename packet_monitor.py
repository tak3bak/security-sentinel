import subprocess
import json
import os
from datetime import datetime

CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")
LOG_OUTPUT_PATH = "/var/log/nomadik_sentinel/packet_telemetry.log"


def ensure_log_dir():
    os.makedirs(os.path.dirname(LOG_OUTPUT_PATH), exist_ok=True)


def start_monitor():
    ensure_log_dir()

    cmd = [
        "tshark",
        "-i",
        CAPTURE_INTERFACE,
        "-T",
        "json",
        "-e",
        "frame.number",
        "-e",
        "frame.len",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.src",
        "-e",
        "ipv6.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "_ws.col.Info",
    ]

    print(f"[*] Starting Nomadik Packet Monitor on {CAPTURE_INTERFACE}")

    while True:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
        )

        buffer = []
        for line in process.stdout:
            buffer.append(line)
            if line.strip() in ["}", "},"]:
                raw_data = "".join(buffer).strip().rstrip(",")
                try:
                    packet_json = json.loads(raw_data)
                    layers = packet_json.get("_source", {}).get("layers", {})

                    def get_field(keys):
                        if isinstance(keys, str):
                            keys = [keys]
                        for k in keys:
                            val = layers.get(k)
                            if isinstance(val, list) and len(val) > 0:
                                return val[0]
                            elif val is not None:
                                return val
                        return None

                    # Extract fields with fallback chaining
                    length = get_field(["frame.len"])
                    if not length or length == "0":
                        buffer = []
                        continue

                    src_ip = get_field(["ip.src", "ipv6.src"])
                    dst_ip = get_field(["ip.dst", "ipv6.dst"])

                    if not src_ip or not dst_ip:
                        buffer = []
                        continue

                    src_port = get_field(["tcp.srcport", "udp.srcport"]) or "N/A"
                    dst_port = get_field(["tcp.dstport", "udp.dstport"]) or "N/A"

                    proto = get_field(["_ws.col.Protocol"])
                    if not proto or proto == "Unknown":
                        if src_port != "N/A" or dst_port != "N/A":
                            proto = "TCP/UDP-Stream"
                        else:
                            proto = "Network-Layer-Packet"

                    info = get_field(["_ws.col.Info"]) or "Captured Active Packet Flow"

                    log_entry = {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "source_port": src_port,
                        "destination_port": dst_port,
                        "protocol": proto,
                        "packet_length": length,
                        "info": info,
                    }

                    with open(LOG_OUTPUT_PATH, "a") as f:
                        f.write(json.dumps(log_entry) + "\n")

                except Exception:
                    pass
                finally:
                    buffer = []


if __name__ == "__main__":
    start_monitor()
