#!/usr/bin/env bash
# ==============================================================================
# Nomadik Security Operations - Backend Test & Verification Runner
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

PROJECT_DIR="$HOME/projects/nomadik-security-sentinel"
cd "${PROJECT_DIR}"

echo -e "${BLUE}[*] Testing Nomadik Security Sentinel Backend...${NC}"
echo -e "Directory: $(pwd)"
echo -e "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'N/A')"

# Step 1: Ensure pytest is available
if ! python3 -m pytest --version &>/dev/null; then
  echo -e "${YELLOW}[!] Installing pytest in Termux environment...${NC}"
  pip install --quiet pytest
fi

# Step 2: Discover and run unit tests
echo -e "\n${BLUE}[*] Executing Core Unit Tests...${NC}"

if [[ -d "tests" ]]; then
  python3 -m pytest tests/ -v --maxfail=5 --tb=short || {
    echo -e "${RED}[ERROR] Test suite encountered failures.${NC}"
    exit 1
  }
  echo -e "\n${GREEN}[SUCCESS] All tests passed.${NC}"
else
  echo -e "${YELLOW}[WARN] No 'tests/' directory found in $(pwd). Listing directory contents:${NC}"
  ls -la
fi

echo -e "\n${GREEN}[+] Backend audit complete.${NC}"
