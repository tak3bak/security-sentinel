#!/usr/bin/env bash
# ==============================================================================
# Script: deploy_ollama_triage.sh
# Target: Debian Workstation / Docker Stack
# Purpose: Optimize local Ollama runtime (Flash Attention, Q8 KV Cache, Batching)
#          and compile the dedicated nomadik-triage:7b engine.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

WORKSPACE_DIR="${HOME}/nomadik/infrastructure/ollama"
MODEL_NAME="nomadik-triage:7b"
BASE_MODEL="qwen2.5-coder:7b"
OLLAMA_ENDPOINT="http://localhost:11434"

mkdir -p "${WORKSPACE_DIR}"
cd "${WORKSPACE_DIR}"

log_info "Writing optimized docker-compose.yml..."
cat << 'EOF' > docker-compose.yml
version: '3.8'

services:
  ollama:
    image: ollama/ollama:latest
    container_name: nomadik-ollama
    restart: unless-stopped
    ports:
      - "11434:11434"
    environment:
      # Memory & compute optimizations
      - OLLAMA_FLASH_ATTENTION=1
      - OLLAMA_KV_CACHE_TYPE=q8_0
      - OLLAMA_GPU_OVERHEAD=1073741824 # 1GB reserved for desktop/host
      - OLLAMA_KEEP_ALIVE=24h
      - OLLAMA_NUM_PARALLEL=4
      - OLLAMA_MAX_QUEUE=512
    volumes:
      - ollama_storage:/root/.ollama
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]

volumes:
  ollama_storage:
    name: nomadik_ollama_storage
EOF

log_info "Restarting Ollama container..."
if docker compose version &> /dev/null; then
    docker compose down || true
    docker compose up -d
elif which docker-compose &> /dev/null; then
    docker-compose down || true
    docker-compose up -d
else
    log_error "Neither 'docker compose' nor 'docker-compose' found."
    exit 1
fi

log_info "Awaiting Ollama API readiness..."
until curl -s "${OLLAMA_ENDPOINT}/api/tags" > /dev/null; do
    sleep 2
done
log_success "Ollama daemon online."

log_info "Pulling base model: ${BASE_MODEL}..."
curl -s -X POST "${OLLAMA_ENDPOINT}/api/pull" -d "{\"name\": \"${BASE_MODEL}\"}" | grep -o '{"status":[^}]*}' | tail -n 1 || true

log_info "Writing Modelfile for ${MODEL_NAME}..."
cat << EOF > Modelfile.triage
FROM ${BASE_MODEL}

# Runtime execution parameters
PARAMETER temperature 0.2
PARAMETER top_p 0.9
PARAMETER num_ctx 8192
PARAMETER num_batch 1024
PARAMETER num_keep 128

# Enforce deterministic security triage formatting
SYSTEM """You are Nomadik Sentinel's local security triage engine.
Analyze telemetry, Wazuh alerts, and audit streams strictly within bounded schemas.
Identify attack vectors, MITRE ATT&CK mappings, and severity ratings.
Output strictly formatted JSON matching the requested schema. Never execute shell actions."""
EOF

log_info "Compiling model ${MODEL_NAME}..."
curl -s -X POST "${OLLAMA_ENDPOINT}/api/create" -d "{
  \"name\": \"${MODEL_NAME}\",
  \"modelfile\": $(jq -Rs . < Modelfile.triage)
}" > /dev/null

log_success "Model ${MODEL_NAME} successfully built."

log_info "Executing verification inference benchmark..."
BENCHMARK_PAYLOAD='{
  "model": "'"${MODEL_NAME}"'",
  "prompt": "Analyze alert: Multiple failed SSH attempts followed by root login from 192.168.1.105. Classify threat.",
  "stream": false
}'

START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST "${OLLAMA_ENDPOINT}/api/generate" -d "${BENCHMARK_PAYLOAD}")
END_TIME=$(date +%s%N)

TOTAL_DURATION=$(( (END_TIME - START_TIME) / 1000000 ))
EVAL_COUNT=$(echo "${RESPONSE}" | jq -r '.eval_count // 0')
EVAL_DURATION=$(echo "${RESPONSE}" | jq -r '.eval_duration // 1')
TOKENS_PER_SEC=$(awk "BEGIN {printf \"%.2f\", (${EVAL_COUNT} / (${EVAL_DURATION} / 1000000000))}")

log_success "Benchmark complete in ${TOTAL_DURATION}ms"
echo "--------------------------------------------------"
echo "Model: ${MODEL_NAME}"
echo "Tokens Generated: ${EVAL_COUNT}"
echo "Throughput: ${TOKENS_PER_SEC} tokens/sec"
echo "--------------------------------------------------"
