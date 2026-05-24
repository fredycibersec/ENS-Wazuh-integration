#!/bin/bash
# ENS Wazuh Integration — SCA Diagnostic Script
# Run as root on the Wazuh manager to diagnose why ENS compliance
# fields are not appearing in OpenSearch Dashboards.
#
# Usage:
#   sudo bash tests/diagnose_sca.sh [opensearch_user] [opensearch_password]
#
# Example:
#   sudo bash tests/diagnose_sca.sh admin MySecretPass
#
# If no credentials are given the script skips OpenSearch checks.

set -euo pipefail

WAZUH_DIR="/var/ossec"
OS_HOST="https://localhost:9200"
OS_USER="${1:-}"
OS_PASS="${2:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
info() { echo -e "${BLUE}[INFO]${NC}  $*"; }
sep()  { echo -e "\n${BLUE}=== $* ===${NC}"; }

echo ""
echo "  ENS Wazuh Integration — SCA Diagnostic"
echo "  $(date)"
echo ""

# -------------------------------------------------------
sep "1. Policy files"
# -------------------------------------------------------

for f in ens_linux.yml ens_windows.yml; do
  path="${WAZUH_DIR}/ruleset/sca/${f}"
  if [[ -f "$path" ]]; then
    ok "Found: ${path}"
  else
    fail "Missing: ${path}"
  fi
done

# -------------------------------------------------------
sep "2. ossec.conf SCA policy references"
# -------------------------------------------------------

if grep -q "ens_linux.yml" "${WAZUH_DIR}/etc/ossec.conf"; then
  info "ossec.conf references ens_linux.yml at:"
  grep "ens_linux\|ens_windows" "${WAZUH_DIR}/etc/ossec.conf" | sed 's/^/       /'
  # Check for wrong path (old bug)
  if grep -q "etc/shared/ens_linux.yml" "${WAZUH_DIR}/etc/ossec.conf"; then
    fail "Path is wrong — references etc/shared/ but files are in ruleset/sca/"
    echo "       Fix: sed -i 's|etc/shared/ens_linux.yml|ruleset/sca/ens_linux.yml|g' ${WAZUH_DIR}/etc/ossec.conf"
    echo "            sed -i 's|etc/shared/ens_windows.yml|ruleset/sca/ens_windows.yml|g' ${WAZUH_DIR}/etc/ossec.conf"
  else
    ok "Policy path looks correct"
  fi
else
  fail "ens_linux.yml not referenced in ossec.conf — SCA policy not configured"
fi

# -------------------------------------------------------
sep "3. Wazuh manager SCA activity (last 100 log lines)"
# -------------------------------------------------------

LOG="${WAZUH_DIR}/logs/ossec.log"
if [[ -f "$LOG" ]]; then
  SCA_LINES=$(grep -i "sca\|ens_linux\|ens_windows" "$LOG" | tail -20 || true)
  if [[ -n "$SCA_LINES" ]]; then
    ok "SCA activity found in ossec.log:"
    echo "$SCA_LINES" | sed 's/^/       /'
  else
    warn "No SCA activity found in ossec.log — policy may not have scanned yet"
  fi
else
  warn "Log file not found: ${LOG}"
fi

# -------------------------------------------------------
sep "4. SCA database — policy results"
# -------------------------------------------------------

DB="${WAZUH_DIR}/queue/db/sca/000.db"
if command -v sqlite3 &>/dev/null && [[ -f "$DB" ]]; then
  POLICY=$(sqlite3 "$DB" "SELECT name, pass, fail, score FROM pm_policy WHERE name LIKE '%ENS%' OR policy_id LIKE '%ens%';" 2>/dev/null || true)
  if [[ -n "$POLICY" ]]; then
    ok "ENS policy found in SCA database:"
    echo "$POLICY" | column -t -s '|' | sed 's/^/       /'
  else
    warn "ENS policy not found in SCA database at ${DB}"
    info "Available policies:"
    sqlite3 "$DB" "SELECT name FROM pm_policy;" 2>/dev/null | sed 's/^/       /' || true
  fi
else
  warn "sqlite3 not available or database not found — skipping SCA DB check"
  info "Install sqlite3 to enable this check: apt install sqlite3 / yum install sqlite"
fi

# -------------------------------------------------------
sep "5. OpenSearch — ENS documents in wazuh-alerts-*"
# -------------------------------------------------------

if [[ -z "$OS_USER" ]]; then
  warn "No OpenSearch credentials provided — skipping OpenSearch checks"
  info "Re-run with: sudo bash $0 <user> <password>"
else
  CURL_BASE="curl -sk -u ${OS_USER}:${OS_PASS}"

  # 5a. Any ENS SCA summary events?
  SUMMARY=$($CURL_BASE "${OS_HOST}/wazuh-alerts-*/_count" \
    -H 'Content-Type: application/json' \
    -d '{"query":{"term":{"data.sca.policy_id":"ens_linux"}}}' 2>/dev/null || echo '{"count":0}')
  COUNT=$(echo "$SUMMARY" | grep -oP '"count":\K[0-9]+' || echo "0")
  if [[ "$COUNT" -gt 0 ]]; then
    ok "ENS summary events in OpenSearch: ${COUNT}"
  else
    fail "No ENS summary events found (data.sca.policy_id: ens_linux) — SCA may not have run yet"
  fi

  # 5b. Any ENS check events with compliance fields?
  CHECK_DOC=$($CURL_BASE "${OS_HOST}/wazuh-alerts-*/_search" \
    -H 'Content-Type: application/json' \
    -d '{"size":1,"_source":["data.sca.check.compliance","data.sca.policy_id","timestamp"],"query":{"bool":{"must":[{"term":{"data.sca.policy_id":"ens_linux"}},{"exists":{"field":"data.sca.check.result"}}]}}}' 2>/dev/null || echo '{"hits":{"total":{"value":0}}}')
  CHECK_COUNT=$(echo "$CHECK_DOC" | grep -oP '"value":\K[0-9]+' | head -1 || echo "0")

  if [[ "$CHECK_COUNT" -gt 0 ]]; then
    ok "ENS check events with data.sca.check.result found: ${CHECK_COUNT}"
    # Show compliance fields from first document
    info "Compliance fields in first check event:"
    echo "$CHECK_DOC" | python3 -c "
import sys, json
doc = json.load(sys.stdin)
hits = doc.get('hits',{}).get('hits',[])
if hits:
    src = hits[0].get('_source',{})
    comp = src.get('data',{}).get('sca',{}).get('check',{}).get('compliance',{})
    if comp:
        for k,v in comp.items():
            print(f'       {k}: {v}')
    else:
        print('       (no compliance fields in document)')
" 2>/dev/null || true
  else
    fail "No ENS check events with data.sca.check.result found in OpenSearch"
    warn "Cause: SCA check results not indexed yet. Force a scan:"
    echo "       ${WAZUH_DIR}/bin/agent_control -r -u <agent_id>"
    echo "       (list agents: ${WAZUH_DIR}/bin/agent_control -l)"
  fi

  # 5c. Field mapping for ENS compliance fields
  MAPPING=$($CURL_BASE "${OS_HOST}/wazuh-alerts-*/_mapping" 2>/dev/null | \
    python3 -c "
import sys, json
try:
    m = json.load(sys.stdin)
    found = []
    for idx, body in m.items():
        props = body.get('mappings',{}).get('properties',{})
        data = props.get('data',{}).get('properties',{}).get('sca',{}).get('properties',{})
        check = data.get('check',{}).get('properties',{}) if data else {}
        comp = check.get('compliance',{}).get('properties',{}) if check else {}
        for k in comp:
            found.append(k)
    if found:
        print('ok:' + ','.join(found))
    else:
        print('missing')
except:
    print('error')
" 2>/dev/null || echo "error")

  if [[ "$MAPPING" == missing ]]; then
    fail "data.sca.check.compliance fields NOT in OpenSearch index mapping"
    warn "Check events have not been indexed yet"
  elif [[ "$MAPPING" == error ]]; then
    warn "Could not parse OpenSearch mapping response"
  else
    FIELDS="${MAPPING#ok:}"
    ok "Compliance fields found in mapping: ${FIELDS}"
    if echo "$FIELDS" | grep -q "ens_nivel"; then
      ok "ens_nivel field present — refresh index pattern in OpenSearch Dashboards"
    else
      warn "ens_nivel NOT in mapping — check events haven't been generated with ENS compliance fields yet"
    fi
  fi
fi

# -------------------------------------------------------
sep "Summary"
# -------------------------------------------------------

echo ""
echo "  Next steps if check events are missing:"
echo ""
echo "  1. List connected agents:"
echo "     ${WAZUH_DIR}/bin/agent_control -l"
echo ""
echo "  2. Force immediate SCA scan on all active agents:"
echo "     ${WAZUH_DIR}/bin/agent_control -r -u 000   # manager itself"
echo "     ${WAZUH_DIR}/bin/agent_control -r -u <id>  # specific agent"
echo ""
echo "  3. Watch for SCA events in real time:"
echo "     tail -f ${WAZUH_DIR}/logs/alerts/alerts.json | grep -i 'ens_linux\\|ens_windows\\|sca'"
echo ""
echo "  4. After check events appear, refresh the index pattern:"
echo "     OpenSearch Dashboards → Management → Index Patterns → wazuh-alerts-* → ⟳"
echo ""
