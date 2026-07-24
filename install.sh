#!/usr/bin/env bash

# ==============================================================================
# NOMADIK ACTIVE DEFENSE SENTINEL ENGINE - AUTOMATED BETA ONBOARDING BOOTSTRAP
# ==============================================================================

set -euo pipefail

# Output styling configurations
C_GREEN='\033[0;32m'
C_CYAN='\033[0;36m'
C_RED='\033[0;31m'
C_NONE='\033[0m'

echo -e "${C_CYAN}🛡️  Initializing Nomadik Sentinel Engine Automated Onboarding Pipeline...${C_NONE}"

# Step 1: Enforce Root Runtime Safety Requirements
if [ "$EUID" -ne 0 ]; then
    echo -e "${C_RED}ERROR: Installation routine must be executed with elevated root permissions.${C_NONE}"
    echo "Please re-execute using: sudo ./install.sh"
    exit 1
fi

# Step 2: Request Beta Credentials to Build Local Environment Environment Matrix
echo -e "\n${C_GREEN}--> Step 1: Commercial Authentication Validation${C_NONE}"
read -p "Enter your Nomadik Closed Beta License Key (NMK-BETA-...): " USER_KEY

if [[ ! "$USER_KEY" =~ ^NMK-BETA- ]] || [ ${#USER_KEY} -lt 20 ]; then
    echo -e "${C_RED}FATAL: Invalid license formatting context given. Deployment terminated.${C_NONE}"
    exit 1
fi

# Step 3: Resolve Critical Native System Packages
echo -e "\n${C_GREEN}--> Step 2: Validating System Core Prerequisites...${C_NONE}"
apt-get update -y && apt-get install -y python3 python3-pip python3-venv git

# Step 4: Isolate Python Virtual Environment to Protect Host Routing Environments
echo -e "\n${C_GREEN}--> Step 3: Isolation Workspace Allocation...${C_NONE}"
INSTALL_DIR="/opt/nomadik-sentinel"
mkdir -p "$INSTALL_DIR"

if [ ! -d "$INSTALL_DIR/.venv" ]; then
    python3 -m venv "$INSTALL_DIR/.venv"
fi

# Activate environment context safely
source "$INSTALL_DIR/.venv/bin/activate"

# Inject core low-level system event watchers and utility layers
pip install --upgrade pip
pip install watchdog python-dotenv requests

# Step 5: Construct Verified Local .env Architecture Blocks
echo -e "\n${C_GREEN}--> Step 4: Assembling Hardened Environment Contexts...${C_NONE}"
ENV_FILE="$INSTALL_DIR/.env"

cat << EOF > "$ENV_FILE"
# NOMADIK AUTOMATED RELEASE MATRIX
DRY_RUN=True
NOMADIK_LICENSE_KEY=$USER_KEY
QUARANTINE_DIR=$INSTALL_DIR/quarantine
LEAK_KEYWORDS=AWS_SECRET_ACCESS_KEY,AWS_ACCESS_KEY_ID,PRIVATE_KEY
SPIDERFOOT_API=http://localhost:5001
SPIDERFOOT_PATH=/opt/spiderfoot
SHODAN_API_KEY=your_shodan_key_here
EOF

chmod 600 "$ENV_FILE"
echo -e "${C_GREEN}✓ Local environment matrix generated securely under: $ENV_FILE${C_NONE}"

echo -e "\n${C_CYAN}==============================================================================${C_NONE}"
echo -e "${C_GREEN}🎉 ONBOARDING BOOTSTRAP COMPLETE in under 60 seconds.${C_NONE}"
echo -e "Your daemon infrastructure workspace is located at: ${C_CYAN}$INSTALL_DIR${C_NONE}"
echo -e "To execute your engine right now in safe trial mode, run:"
echo -e "  ${C_CYAN}sudo $INSTALL_DIR/.venv/bin/python sentinel.py${C_NONE}"
echo -e "${C_CYAN}==============================================================================${C_NONE}"
