#!/bin/bash
# ENS Wazuh Integration — API Sync Installer
# Installs the Wazuh API → OpenSearch bridge and check-level ENS dashboard.
#
# Run as root on the Wazuh manager after the main install.sh has been applied:
#
#   sudo bash install_sync.sh
#
# Credentials can be supplied via environment variables to skip prompts:
#
#   sudo WAZUH_PASS='xxx' OS_PASS='yyy' bash install_sync.sh
#
# https://github.com/fredycibersec/ENS-Wazuh-integration

set -euo pipefail

# ── Defaults ───────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ENS-Wazuh-integration"
WAZUH_HOST="${WAZUH_HOST:-https://localhost:55000}"
WAZUH_USER="${WAZUH_USER:-wazuh-wui}"
WAZUH_PASS="${WAZUH_PASS:-}"
OS_HOST="${OS_HOST:-https://localhost:9200}"
OS_USER="${OS_USER:-admin}"
OS_PASS="${OS_PASS:-}"
OSD_HOST="${OSD_HOST:-https://localhost:443}"   # OpenSearch Dashboards
CRON_FILE="/etc/cron.d/ens-sca-sync"
LOG_FILE="/var/log/ens-sca-sync.log"
TAR_SEARCH_PATHS=(/root /home /tmp /var/tmp)

# ── Colors ─────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
sep()   { echo -e "\n${BLUE}══════════════════════════════════════${NC}"; echo -e "${BLUE}  $*${NC}"; echo -e "${BLUE}══════════════════════════════════════${NC}"; }

echo ""
echo "  ENS Wazuh Integration — API Sync Installer"
echo "  https://github.com/fredycibersec/ENS-Wazuh-integration"
echo ""

# ── 1. Root check ──────────────────────────────────────────────────────────────

[[ $EUID -ne 0 ]] && error "This script must be run as root."

# ── 2. Python3 check ───────────────────────────────────────────────────────────

sep "Checking prerequisites"

PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null && "$cmd" -c "import sys; sys.exit(0 if sys.version_info >= (3,6) else 1)" 2>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done
[[ -n "$PYTHON" ]] || error "Python 3.6+ is required. Install it with: apt install python3 / yum install python3"
ok "Python: $($PYTHON --version 2>&1)"

# Install requests if missing
if ! $PYTHON -c "import requests" 2>/dev/null; then
    info "Installing requests library..."
    if command -v pip3 &>/dev/null; then
        pip3 install -q requests
    elif command -v pip &>/dev/null; then
        pip install -q requests
    else
        $PYTHON -m ensurepip --upgrade 2>/dev/null || true
        $PYTHON -m pip install -q requests
    fi
    $PYTHON -c "import requests" || error "Failed to install 'requests'. Run manually: pip3 install requests"
fi
ok "requests library: available"

command -v curl &>/dev/null || error "curl is required. Install it with: apt install curl / yum install curl"
ok "curl: $(curl --version | head -1)"

# ── 3. Credential detection ────────────────────────────────────────────────────

sep "Credentials"

try_extract_from_tar() {
    local tar_file="$1"
    local field="$2"
    tar -xOf "$tar_file" wazuh-install-files/wazuh-passwords.txt 2>/dev/null | \
        grep -A1 "^# $field" | grep "password:" | awk '{print $NF}' || true
}

find_tar() {
    for dir in "${TAR_SEARCH_PATHS[@]}"; do
        local found
        found=$(find "$dir" -maxdepth 2 -name "wazuh-install-files.tar" 2>/dev/null | head -1 || true)
        if [[ -n "$found" ]]; then
            echo "$found"
            return
        fi
    done
}

INSTALL_TAR=$(find_tar || true)

if [[ -n "$INSTALL_TAR" ]]; then
    info "Found installation archive: ${INSTALL_TAR}"
    if [[ -z "$WAZUH_PASS" ]]; then
        WAZUH_PASS=$(try_extract_from_tar "$INSTALL_TAR" "Wazuh API")
        [[ -n "$WAZUH_PASS" ]] && info "Wazuh API password read from tar"
    fi
    if [[ -z "$OS_PASS" ]]; then
        OS_PASS=$(try_extract_from_tar "$INSTALL_TAR" "OpenSearch")
        # Fallback: look for 'admin' user entry
        if [[ -z "$OS_PASS" ]]; then
            OS_PASS=$(tar -xOf "$INSTALL_TAR" wazuh-install-files/wazuh-passwords.txt 2>/dev/null | \
                grep -A1 "user: admin" | grep "password:" | awk '{print $NF}' || true)
        fi
        [[ -n "$OS_PASS" ]] && info "OpenSearch password read from tar"
    fi
else
    warn "wazuh-install-files.tar not found — will prompt for credentials"
fi

prompt_if_empty() {
    local var_name="$1"
    local prompt_text="$2"
    local current_val="${!var_name:-}"
    if [[ -z "$current_val" ]]; then
        read -rsp "  ${prompt_text}: " input
        echo ""
        printf -v "$var_name" '%s' "$input"
    fi
}

prompt_if_empty WAZUH_PASS "Wazuh API password (user: ${WAZUH_USER})"
prompt_if_empty OS_PASS    "OpenSearch password (user: ${OS_USER})"

[[ -n "$WAZUH_PASS" ]] || error "Wazuh API password is required."
[[ -n "$OS_PASS" ]]    || error "OpenSearch password is required."

# ── 4. Connectivity tests ──────────────────────────────────────────────────────

sep "Testing connectivity"

info "Testing Wazuh API at ${WAZUH_HOST}..."
WAZUH_TOKEN=$(curl -sk -u "${WAZUH_USER}:${WAZUH_PASS}" \
    -X POST "${WAZUH_HOST}/security/user/authenticate" 2>/dev/null | \
    $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(d['data']['token'])" 2>/dev/null) || true

if [[ -z "$WAZUH_TOKEN" ]]; then
    error "Cannot authenticate to Wazuh API at ${WAZUH_HOST}. Check WAZUH_HOST / credentials."
fi
ok "Wazuh API: authenticated"

info "Testing OpenSearch at ${OS_HOST}..."
OS_STATUS=$(curl -sk -u "${OS_USER}:${OS_PASS}" "${OS_HOST}/_cluster/health" 2>/dev/null | \
    $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null) || true

if [[ -z "$OS_STATUS" || "$OS_STATUS" == "unknown" ]]; then
    error "Cannot connect to OpenSearch at ${OS_HOST}. Check OS_HOST / credentials."
fi
ok "OpenSearch cluster: ${OS_STATUS}"

# ── 5. Install sync script ─────────────────────────────────────────────────────

sep "Installing sync script"

mkdir -p "${INSTALL_DIR}/tools"
cp "${SCRIPT_DIR}/tools/sync_sca_to_opensearch.py" "${INSTALL_DIR}/tools/"
chmod 750 "${INSTALL_DIR}/tools/sync_sca_to_opensearch.py"
ok "Script installed at ${INSTALL_DIR}/tools/sync_sca_to_opensearch.py"

# ── 6. Dry run ─────────────────────────────────────────────────────────────────

sep "Running dry-run sync"

info "Fetching SCA checks from Wazuh API (no writes)..."
DRY_OUTPUT=$(WAZUH_HOST="$WAZUH_HOST" WAZUH_USER="$WAZUH_USER" WAZUH_PASS="$WAZUH_PASS" \
             OS_HOST="$OS_HOST" OS_USER="$OS_USER" OS_PASS="$OS_PASS" \
             $PYTHON "${INSTALL_DIR}/tools/sync_sca_to_opensearch.py" --dry-run 2>&1) || {
    warn "Dry-run produced errors:"
    echo "$DRY_OUTPUT" | sed 's/^/    /'
    warn "Continuing anyway — cron will retry once agents have completed their first SCA scan."
}

if echo "$DRY_OUTPUT" | grep -q "documents built"; then
    DOC_COUNT=$(echo "$DRY_OUTPUT" | grep -oP '\d+ documents built' | grep -oP '\d+' || echo "?")
    ok "Dry-run: ${DOC_COUNT} documents ready to index"
else
    warn "No documents found yet (agents may not have finished an SCA scan)"
fi

# ── 7. First real sync ─────────────────────────────────────────────────────────

sep "Running first sync"

info "Indexing SCA check results into OpenSearch..."
SYNC_OUTPUT=$(WAZUH_HOST="$WAZUH_HOST" WAZUH_USER="$WAZUH_USER" WAZUH_PASS="$WAZUH_PASS" \
              OS_HOST="$OS_HOST" OS_USER="$OS_USER" OS_PASS="$OS_PASS" \
              $PYTHON "${INSTALL_DIR}/tools/sync_sca_to_opensearch.py" 2>&1) || true

echo "$SYNC_OUTPUT" | sed 's/^/    /'

if echo "$SYNC_OUTPUT" | grep -q "indexed [^0]"; then
    ok "First sync completed successfully"
else
    warn "No documents indexed yet — this is normal before the first SCA scan completes"
fi

# ── 8. Cron setup ──────────────────────────────────────────────────────────────

sep "Setting up cron job"

touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

PYTHON_PATH=$(command -v "$PYTHON")

cat > "$CRON_FILE" <<CRONEOF
# ENS SCA → OpenSearch sync — generated by install_sync.sh
# Polls Wazuh API every 15 minutes and upserts check results into ens-sca-checks
WAZUH_HOST=${WAZUH_HOST}
WAZUH_USER=${WAZUH_USER}
WAZUH_PASS=${WAZUH_PASS}
OS_HOST=${OS_HOST}
OS_USER=${OS_USER}
OS_PASS=${OS_PASS}
OS_INDEX=ens-sca-checks

*/15 * * * * root ${PYTHON_PATH} ${INSTALL_DIR}/tools/sync_sca_to_opensearch.py >> ${LOG_FILE} 2>&1
CRONEOF

chmod 600 "$CRON_FILE"
ok "Cron job installed at ${CRON_FILE} (every 15 minutes)"
info "Logs will be written to ${LOG_FILE}"

# ── 9. Import dashboard ────────────────────────────────────────────────────────

sep "Importing dashboard into OpenSearch Dashboards"

NDJSON="${SCRIPT_DIR}/dashboards/ens_sca_checks_dashboard.ndjson"

if [[ ! -f "$NDJSON" ]]; then
    warn "Dashboard file not found: ${NDJSON} — skipping import"
else
    info "Importing ${NDJSON} into ${OSD_HOST}..."
    HTTP_CODE=$(curl -sk -o /tmp/osd_import_response.json -w "%{http_code}" \
        -u "${OS_USER}:${OS_PASS}" \
        -X POST "${OSD_HOST}/api/saved_objects/_import?overwrite=true" \
        -H "osd-xsrf: true" \
        --form "file=@${NDJSON}" 2>/dev/null) || HTTP_CODE="000"

    if [[ "$HTTP_CODE" == "200" ]]; then
        IMPORT_SUCCESS=$($PYTHON -c "
import json, sys
try:
    d = json.load(open('/tmp/osd_import_response.json'))
    print('ok' if d.get('success') else 'partial')
except:
    print('unknown')
" 2>/dev/null)
        if [[ "$IMPORT_SUCCESS" == "ok" ]]; then
            ok "Dashboard imported successfully"
            info "Go to: ${OSD_HOST} → Dashboards → ENS — SCA Check-Level Compliance"
        else
            warn "Dashboard import returned partial success — check saved objects for errors"
            cat /tmp/osd_import_response.json | $PYTHON -m json.tool 2>/dev/null | head -30 | sed 's/^/    /'
        fi
    elif [[ "$HTTP_CODE" == "000" ]]; then
        warn "Could not reach OpenSearch Dashboards at ${OSD_HOST}"
        warn "Import manually: Dashboards → Stack Management → Saved Objects → Import"
        warn "File: dashboards/ens_sca_checks_dashboard.ndjson"
    else
        warn "Dashboard import returned HTTP ${HTTP_CODE}"
        warn "Try manually: Dashboards → Stack Management → Saved Objects → Import"
        info "If your Dashboards port is different, re-run with:"
        info "  sudo OSD_HOST=https://localhost:5601 bash install_sync.sh"
    fi
fi

# ── 10. Summary ────────────────────────────────────────────────────────────────

sep "Installation complete"

echo ""
echo -e "  ${GREEN}✔${NC}  Sync script:   ${INSTALL_DIR}/tools/sync_sca_to_opensearch.py"
echo -e "  ${GREEN}✔${NC}  Cron job:      ${CRON_FILE}  (every 15 min)"
echo -e "  ${GREEN}✔${NC}  Log file:      ${LOG_FILE}"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Wait for the next SCA scan to complete (or force one):"
echo "     /var/ossec/bin/agent_control -r -u <agent_id>"
echo ""
echo "  2. Watch sync logs:"
echo "     tail -f ${LOG_FILE}"
echo ""
echo "  3. Verify documents in OpenSearch:"
echo "     curl -sk -u ${OS_USER}:PASS '${OS_HOST}/ens-sca-checks/_count' | python3 -m json.tool"
echo ""
echo "  4. Open the dashboard:"
echo "     ${OSD_HOST} → Dashboards → ENS — SCA Check-Level Compliance"
echo ""
echo "  To change the sync interval, edit ${CRON_FILE}"
echo "  To uninstall the sync tool, run: sudo bash uninstall_sync.sh"
echo ""
