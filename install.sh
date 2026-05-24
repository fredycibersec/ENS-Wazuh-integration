#!/bin/bash
# ENS Wazuh Integration — Installer
# https://github.com/fredycibersec/ENS-Wazuh-integration

set -euo pipefail

WAZUH_DIR="/var/ossec"
SCA_DIR="${WAZUH_DIR}/ruleset/sca"
RULES_DIR="${WAZUH_DIR}/etc/rules"
OSSEC_CONF="${WAZUH_DIR}/etc/ossec.conf"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

echo ""
echo "  ENS Wazuh Integration — Installer"
echo "  https://github.com/fredycibersec/ENS-Wazuh-integration"
echo ""

# --- Checks ---

[[ $EUID -ne 0 ]] && error "This script must be run as root."

[[ -d "$WAZUH_DIR" ]] || error "Wazuh directory not found at ${WAZUH_DIR}. Is Wazuh manager installed?"

WAZUH_VERSION=$(${WAZUH_DIR}/bin/wazuh-control info 2>/dev/null | grep -i "wazuh_version" | grep -oP 'v[0-9]+\.[0-9]+\.[0-9]+' || true)
info "Detected Wazuh: ${WAZUH_VERSION:-unknown version}"

MAJOR=$(echo "$WAZUH_VERSION" | grep -oP 'v\K[0-9]+' | head -1 || echo "0")
[[ "$MAJOR" -ge 4 ]] || warn "Wazuh 4.x or later is recommended. Detected major version: ${MAJOR}"

# --- Backup ---

BACKUP_DIR="${WAZUH_DIR}/backup/ens-integration-$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"
info "Backup directory: ${BACKUP_DIR}"

[[ -f "${OSSEC_CONF}" ]] && cp "${OSSEC_CONF}" "${BACKUP_DIR}/ossec.conf.bak"

# --- Install SCA policies ---

info "Installing SCA policies..."
cp "${SCRIPT_DIR}/sca/ens_linux.yml" "${SCA_DIR}/"
cp "${SCRIPT_DIR}/sca/ens_windows.yml" "${SCA_DIR}/"
chown root:wazuh "${SCA_DIR}/ens_linux.yml" "${SCA_DIR}/ens_windows.yml"
chmod 640 "${SCA_DIR}/ens_linux.yml" "${SCA_DIR}/ens_windows.yml"
info "SCA policies installed at ${SCA_DIR}/"

# --- Install detection rules ---

info "Installing detection rules..."
cp "${SCRIPT_DIR}/rules/ens_detection_rules.xml" "${RULES_DIR}/"
chown root:wazuh "${RULES_DIR}/ens_detection_rules.xml"
chmod 640 "${RULES_DIR}/ens_detection_rules.xml"
info "Detection rules installed at ${RULES_DIR}/"

# --- Update ossec.conf ---

if grep -q "ens_linux.yml" "${OSSEC_CONF}"; then
  warn "ENS SCA policies already referenced in ossec.conf. Skipping configuration update."
else
  info "Adding ENS SCA policies to ossec.conf..."
  if grep -q "<sca>" "${OSSEC_CONF}"; then
    # Insert policy references inside existing <sca> block
    sed -i "/<sca>/a\\    <policies>\\n      <policy>etc\/shared\/ens_linux.yml<\/policy>\\n      <policy>etc\/shared\/ens_windows.yml<\/policy>\\n    <\/policies>" "${OSSEC_CONF}"
    info "ENS policies added to existing <sca> block."
  else
    warn "No <sca> block found in ossec.conf. Please add the following manually:"
    echo ""
    echo "  <sca>"
    echo "    <enabled>yes</enabled>"
    echo "    <scan_on_start>yes</scan_on_start>"
    echo "    <interval>12h</interval>"
    echo "    <policies>"
    echo "      <policy>etc/shared/ens_linux.yml</policy>"
    echo "      <policy>etc/shared/ens_windows.yml</policy>"
    echo "    </policies>"
    echo "  </sca>"
    echo ""
  fi
fi

# --- Validate configuration ---

info "Validating Wazuh configuration..."
if "${WAZUH_DIR}/bin/wazuh-analysisd" -t 2>/dev/null; then
  info "Configuration validation passed."
else
  warn "Configuration validation returned warnings. Check ossec.conf manually."
fi

# --- Restart Wazuh manager ---

read -rp "Restart Wazuh manager now? [y/N] " answer
if [[ "${answer,,}" == "y" ]]; then
  info "Restarting Wazuh manager..."
  systemctl restart wazuh-manager
  info "Wazuh manager restarted."
else
  warn "Restart skipped. Run 'systemctl restart wazuh-manager' to apply changes."
fi

echo ""
info "ENS integration installed successfully."
info "SCA results will appear in Wazuh dashboard → Security Configuration Assessment."
info "Detection rule alerts will include ENS_ groups in the compliance tags."
echo ""
echo -e "${YELLOW}--- Next steps ---${NC}"
echo ""
echo "  1. Import the ENS dashboard:"
echo "     OpenSearch Dashboards → Management → Saved Objects → Import"
echo "     File: dashboards/ens_dashboard.ndjson"
echo ""
echo "  2. After the first SCA scan completes, refresh the index pattern"
echo "     so all ENS compliance fields are discovered:"
echo ""
echo "     OpenSearch Dashboards → Management → Index Patterns"
echo "     → wazuh-alerts-* → click the Refresh fields button (⟳)"
echo ""
echo "     Or via API (replace credentials as needed):"
echo "     curl -X POST 'https://localhost:9200/wazuh-alerts-*/_field_caps?fields=data.sca.check.compliance.*' \\"
echo "       -u <user>:<password> --insecure"
echo ""
echo "  3. Force an immediate SCA scan on an agent (optional):"
echo "     /var/ossec/bin/agent_control -r -u <agent_id>"
echo ""
