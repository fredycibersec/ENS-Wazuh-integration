#!/bin/bash
# ENS Wazuh Integration — API Sync Uninstaller

set -euo pipefail

INSTALL_DIR="/opt/ENS-Wazuh-integration"
CRON_FILE="/etc/cron.d/ens-sca-sync"
LOG_FILE="/var/log/ens-sca-sync.log"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

echo ""
echo "  ENS Wazuh Integration — API Sync Uninstaller"
echo ""

[[ -f "$CRON_FILE" ]] && { rm -f "$CRON_FILE"; info "Removed cron job: ${CRON_FILE}"; } || warn "Cron file not found: ${CRON_FILE}"

[[ -f "${INSTALL_DIR}/tools/sync_sca_to_opensearch.py" ]] && {
    rm -f "${INSTALL_DIR}/tools/sync_sca_to_opensearch.py"
    info "Removed sync script"
} || warn "Sync script not found"

rmdir "${INSTALL_DIR}/tools" 2>/dev/null && info "Removed ${INSTALL_DIR}/tools" || true
rmdir "${INSTALL_DIR}"       2>/dev/null && info "Removed ${INSTALL_DIR}" || true

echo ""
echo "  The ens-sca-checks OpenSearch index has NOT been deleted."
echo "  To delete it (removes all indexed check data):"
echo "    curl -sk -u admin:PASS -X DELETE 'https://localhost:9200/ens-sca-checks'"
echo ""
echo "  Log file kept at: ${LOG_FILE}"
echo "  Remove manually with: rm ${LOG_FILE}"
echo ""
