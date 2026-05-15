#!/bin/bash
# ENS Wazuh Integration — Uninstaller
# https://github.com/fredycibersec/ENS-Wazuh-integration

set -euo pipefail

WAZUH_DIR="/var/ossec"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && error "This script must be run as root."

info "Removing ENS SCA policies..."
rm -f "${WAZUH_DIR}/ruleset/sca/ens_linux.yml"
rm -f "${WAZUH_DIR}/ruleset/sca/ens_windows.yml"

info "Removing ENS detection rules..."
rm -f "${WAZUH_DIR}/etc/rules/ens_detection_rules.xml"

warn "ossec.conf was not modified. Remove ENS policy references manually if needed."

read -rp "Restart Wazuh manager now? [y/N] " answer
[[ "${answer,,}" == "y" ]] && systemctl restart wazuh-manager

info "ENS integration removed."
