#!/bin/bash
# ENS Wazuh Integration — SCA Agent Deployment
# Creates Wazuh groups for ENS policies and assigns agents automatically
# based on their OS (Linux → ens-linux, Windows → ens-windows).
#
# Run as root on the Wazuh manager:
#
#   sudo bash deploy_sca_agents.sh
#
# Credentials are read from wazuh-install-files.tar automatically.
# Override with environment variables if needed:
#
#   sudo WAZUH_USER=wazuh WAZUH_PASS='xxx' bash deploy_sca_agents.sh
#
# Options:
#   --dry-run      Show what would be done without making changes
#   --force-scan   Force an immediate SCA scan on all assigned agents
#   --no-assign    Create groups and files only; skip agent assignment
#
# https://github.com/fredycibersec/ENS-Wazuh-integration

set -euo pipefail

# ── Defaults ───────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_DIR="/var/ossec"
WAZUH_HOST="${WAZUH_HOST:-https://localhost:55000}"
WAZUH_USER="${WAZUH_USER:-}"
WAZUH_PASS="${WAZUH_PASS:-}"
TAR_SEARCH_PATHS=(/root /home /tmp /var/tmp)
GROUP_LINUX="ens-linux"
GROUP_WINDOWS="ens-windows"
DRY_RUN=false
FORCE_SCAN=false
NO_ASSIGN=false

# ── Parse arguments ────────────────────────────────────────────────────────────

for arg in "$@"; do
  case "$arg" in
    --dry-run)    DRY_RUN=true ;;
    --force-scan) FORCE_SCAN=true ;;
    --no-assign)  NO_ASSIGN=true ;;
    *) echo "Unknown option: $arg"; exit 1 ;;
  esac
done

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
dry()   { echo -e "  ${YELLOW}[DRY-RUN]${NC} $*"; }

echo ""
echo "  ENS Wazuh Integration — SCA Agent Deployment"
echo "  https://github.com/fredycibersec/ENS-Wazuh-integration"
$DRY_RUN && echo -e "  ${YELLOW}DRY-RUN mode — no changes will be made${NC}"
echo ""

# ── Checks ─────────────────────────────────────────────────────────────────────

[[ $EUID -ne 0 ]] && error "This script must be run as root."
[[ -d "$WAZUH_DIR" ]] || error "Wazuh not found at ${WAZUH_DIR}."
command -v python3 &>/dev/null || error "python3 is required."
command -v curl    &>/dev/null || error "curl is required."

# ── Credential detection ───────────────────────────────────────────────────────

sep "Credentials"

find_tar() {
    for dir in "${TAR_SEARCH_PATHS[@]}"; do
        local f
        f=$(find "$dir" -maxdepth 2 -name "wazuh-install-files.tar" 2>/dev/null | head -1 || true)
        [[ -n "$f" ]] && echo "$f" && return
    done
}

extract_password() {
    local content="$1" username="$2"
    python3 - <<PYEOF
content = """$content"""
username = "$username"
user_keys = ("api_username:", "username:")
pass_keys = ("api_password:", "password:")
lines = content.splitlines()
for i, line in enumerate(lines):
    s = line.strip()
    for uk in user_keys:
        if s.startswith(uk):
            val = s[len(uk):].strip().strip("\"'")
            if val == username:
                for j in range(i+1, min(i+4, len(lines))):
                    pl = lines[j].strip()
                    for pk in pass_keys:
                        if pl.startswith(pk):
                            print(pl[len(pk):].strip().strip("\"'"))
                            exit(0)
PYEOF
}

INSTALL_TAR=$(find_tar || true)

if [[ -n "$INSTALL_TAR" ]]; then
    info "Found installation archive: ${INSTALL_TAR}"
    PASSWORDS_CONTENT=$(python3 -c "
import tarfile, sys
paths = ['wazuh-install-files/wazuh-passwords.txt', 'wazuh-passwords.txt']
with tarfile.open('${INSTALL_TAR}') as tf:
    for p in paths:
        try:
            print(tf.extractfile(tf.getmember(p)).read().decode('utf-8', errors='replace'))
            break
        except KeyError:
            pass
" 2>/dev/null || true)

    if [[ -n "$PASSWORDS_CONTENT" ]]; then
        if [[ -z "$WAZUH_USER" || -z "$WAZUH_PASS" ]]; then
            for api_user in wazuh wazuh-wui; do
                candidate=$(extract_password "$PASSWORDS_CONTENT" "$api_user" || true)
                if [[ -n "$candidate" ]]; then
                    [[ -z "$WAZUH_USER" ]] && WAZUH_USER="$api_user"
                    [[ -z "$WAZUH_PASS" ]] && WAZUH_PASS="$candidate"
                    info "Wazuh API credentials: user=${WAZUH_USER}  pass=${WAZUH_PASS:0:6}***  (from tar)"
                    break
                fi
            done
        fi
    else
        warn "Could not read passwords file from tar"
    fi
fi

# Fallback to prompts
if [[ -z "$WAZUH_USER" ]]; then
    read -rp "  Wazuh API username [wazuh]: " WAZUH_USER
    WAZUH_USER="${WAZUH_USER:-wazuh}"
fi
if [[ -z "$WAZUH_PASS" ]]; then
    read -rsp "  Wazuh API password: " WAZUH_PASS; echo ""
fi
[[ -n "$WAZUH_PASS" ]] || error "Wazuh API password is required."

# ── Wazuh API helpers ──────────────────────────────────────────────────────────

api_token() {
    python3 -c "
import urllib.request, urllib.error, json, base64, ssl
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
creds = base64.b64encode(b'${WAZUH_USER}:${WAZUH_PASS}').decode()
req = urllib.request.Request('${WAZUH_HOST}/security/user/authenticate',
    method='POST', headers={'Authorization': 'Basic ' + creds})
try:
    r = urllib.request.urlopen(req, context=ctx, timeout=10)
    print(json.load(r)['data']['token'])
except urllib.error.HTTPError as e:
    import sys; sys.stderr.write(f'401: check WAZUH_USER / WAZUH_PASS\n'); sys.exit(1)
" 2>/dev/null
}

api_get() {
    local token="$1" path="$2" params="${3:-}"
    curl -sk -H "Authorization: Bearer ${token}" \
        "${WAZUH_HOST}${path}${params:+?}${params}" 2>/dev/null
}

sep "Connecting to Wazuh API"

TOKEN=$(api_token) || error "Authentication failed. Check WAZUH_USER / WAZUH_PASS."
ok "Authenticated as ${WAZUH_USER}"

# ── Fetch active agents ────────────────────────────────────────────────────────

sep "Fetching agents"

AGENTS_JSON=$(api_get "$TOKEN" "/agents" "status=active&limit=500&select=id,name,os")

AGENT_COUNT=$(echo "$AGENTS_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d['data']['total_affected_items'])
" 2>/dev/null || echo 0)

info "Active agents found: ${AGENT_COUNT}"

# Parse agent list into arrays: ID|name|os_platform
mapfile -t AGENT_LIST < <(echo "$AGENTS_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for a in d['data']['affected_items']:
    if a['id'] == '000':
        continue
    platform = a.get('os', {}).get('platform', 'unknown').lower()
    print(f\"{a['id']}|{a.get('name', a['id'])}|{platform}\")
" 2>/dev/null || true)

LINUX_AGENTS=()
WINDOWS_AGENTS=()
UNKNOWN_AGENTS=()

for entry in "${AGENT_LIST[@]}"; do
    id="${entry%%|*}"
    rest="${entry#*|}"
    name="${rest%%|*}"
    platform="${rest##*|}"

    if [[ "$platform" == "windows" ]]; then
        WINDOWS_AGENTS+=("$id|$name")
    elif [[ "$platform" == "unknown" ]]; then
        UNKNOWN_AGENTS+=("$id|$name")
    else
        LINUX_AGENTS+=("$id|$name")
    fi
done

echo ""
echo "  Linux agents  (→ ${GROUP_LINUX}):   ${#LINUX_AGENTS[@]}"
for e in "${LINUX_AGENTS[@]}"; do
    echo "    id=${e%%|*}  name=${e##*|}"
done

echo "  Windows agents (→ ${GROUP_WINDOWS}): ${#WINDOWS_AGENTS[@]}"
for e in "${WINDOWS_AGENTS[@]}"; do
    echo "    id=${e%%|*}  name=${e##*|}"
done

if [[ ${#UNKNOWN_AGENTS[@]} -gt 0 ]]; then
    warn "Agents with unknown OS (will not be assigned): ${#UNKNOWN_AGENTS[@]}"
    for e in "${UNKNOWN_AGENTS[@]}"; do
        echo "    id=${e%%|*}  name=${e##*|}"
    done
fi

# ── Create groups and copy policy files ───────────────────────────────────────

sep "Setting up Wazuh groups"

create_group() {
    local group="$1"
    if [[ -d "${WAZUH_DIR}/etc/shared/${group}" ]]; then
        ok "Group '${group}' already exists"
        return
    fi
    if $DRY_RUN; then
        dry "Would create group: ${group}"
        return
    fi
    "${WAZUH_DIR}/bin/agent_groups" -a -g "$group" -q 2>/dev/null \
        || warn "Could not create group '${group}' via agent_groups (may already exist)"
    mkdir -p "${WAZUH_DIR}/etc/shared/${group}"
    ok "Group '${group}' created"
}

write_agent_conf() {
    local group="$1" policy_file="$2"
    local conf="${WAZUH_DIR}/etc/shared/${group}/agent.conf"
    local content="<agent_config>
  <sca>
    <policies>
      <policy>etc/shared/${policy_file}</policy>
    </policies>
  </sca>
</agent_config>"

    if $DRY_RUN; then
        dry "Would write ${conf}"
        return
    fi
    echo "$content" > "$conf"
    chown wazuh:wazuh "$conf"
    chmod 640 "$conf"
    ok "agent.conf written for group '${group}'"
}

copy_policy() {
    local src="$1" dst_dir="$2" filename="$3"
    if [[ ! -f "$src" ]]; then
        warn "Policy file not found: ${src} — skipping"
        return
    fi
    if $DRY_RUN; then
        dry "Would copy ${src} → ${dst_dir}/${filename}"
        return
    fi
    cp "$src" "${dst_dir}/${filename}"
    chown wazuh:wazuh "${dst_dir}/${filename}"
    chmod 640 "${dst_dir}/${filename}"
    ok "Policy copied to ${dst_dir}/${filename}"
}

# Linux group
if [[ ${#LINUX_AGENTS[@]} -gt 0 ]] || ! $NO_ASSIGN; then
    create_group "$GROUP_LINUX"
    copy_policy "${SCRIPT_DIR}/sca/ens_linux.yml" \
                "${WAZUH_DIR}/etc/shared/${GROUP_LINUX}" \
                "ens_linux.yml"
    write_agent_conf "$GROUP_LINUX" "ens_linux.yml"
fi

# Windows group
if [[ ${#WINDOWS_AGENTS[@]} -gt 0 ]] || ! $NO_ASSIGN; then
    create_group "$GROUP_WINDOWS"
    copy_policy "${SCRIPT_DIR}/sca/ens_windows.yml" \
                "${WAZUH_DIR}/etc/shared/${GROUP_WINDOWS}" \
                "ens_windows.yml"
    write_agent_conf "$GROUP_WINDOWS" "ens_windows.yml"
fi

# ── Assign agents to groups ────────────────────────────────────────────────────

if $NO_ASSIGN; then
    info "Skipping agent assignment (--no-assign)"
else
    sep "Assigning agents to groups"

    assign_agent() {
        local agent_id="$1" group="$2" name="$3"
        # Check if already in group
        local current_groups
        current_groups=$(api_get "$TOKEN" "/agents/${agent_id}/group" "" | \
            python3 -c "
import sys, json
d = json.load(sys.stdin)
groups = [g['name'] for g in d.get('data', {}).get('affected_items', [])]
print(','.join(groups))
" 2>/dev/null || true)

        if echo "$current_groups" | grep -qw "$group"; then
            ok "agent=${name} (${agent_id}) already in group '${group}'"
            return
        fi

        if $DRY_RUN; then
            dry "Would assign agent=${name} (${agent_id}) → group '${group}'"
            return
        fi

        "${WAZUH_DIR}/bin/agent_groups" -a -i "$agent_id" -g "$group" -q 2>/dev/null \
            && ok "agent=${name} (${agent_id}) → group '${group}'" \
            || warn "Could not assign agent ${agent_id} to group '${group}'"
    }

    for entry in "${LINUX_AGENTS[@]}"; do
        assign_agent "${entry%%|*}" "$GROUP_LINUX" "${entry##*|}"
    done

    for entry in "${WINDOWS_AGENTS[@]}"; do
        assign_agent "${entry%%|*}" "$GROUP_WINDOWS" "${entry##*|}"
    done
fi

# ── Force SCA scan ─────────────────────────────────────────────────────────────

if $FORCE_SCAN; then
    sep "Forcing SCA scan"
    ALL_ASSIGNED=("${LINUX_AGENTS[@]}" "${WINDOWS_AGENTS[@]}")
    if [[ ${#ALL_ASSIGNED[@]} -eq 0 ]]; then
        warn "No agents to scan"
    fi
    for entry in "${ALL_ASSIGNED[@]}"; do
        agent_id="${entry%%|*}"
        name="${entry##*|}"
        if $DRY_RUN; then
            dry "Would force scan on agent=${name} (${agent_id})"
        else
            "${WAZUH_DIR}/bin/agent_control" -r -u "$agent_id" 2>/dev/null \
                && ok "Scan triggered: agent=${name} (${agent_id})" \
                || warn "Could not trigger scan on agent ${agent_id}"
        fi
    done
fi

# ── Summary ────────────────────────────────────────────────────────────────────

sep "Summary"

echo ""
LINUX_COUNT=${#LINUX_AGENTS[@]}
WINDOWS_COUNT=${#WINDOWS_AGENTS[@]}

if $DRY_RUN; then
    echo -e "  ${YELLOW}DRY-RUN — no changes were made${NC}"
    echo ""
fi

echo -e "  ${GREEN}✔${NC}  Group '${GROUP_LINUX}'   — ${LINUX_COUNT} agent(s) assigned"
echo -e "  ${GREEN}✔${NC}  Group '${GROUP_WINDOWS}' — ${WINDOWS_COUNT} agent(s) assigned"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Wazuh pushes policy files to agents automatically (1–2 min)."
echo "     Watch synchronisation:"
echo "     tail -f ${WAZUH_DIR}/logs/ossec.log | grep -i 'sca\\|ens'"
echo ""
if ! $FORCE_SCAN; then
    echo "  2. Force an immediate scan on all assigned agents:"
    echo "     sudo bash $0 --force-scan"
    echo ""
    echo "  3. After the scan, run the API sync to index results:"
else
    echo "  2. After the scan completes, run the API sync to index results:"
fi
echo "     sudo python3 ${WAZUH_DIR/\/var\/ossec//opt/ENS-Wazuh-integration}/tools/sync_sca_to_opensearch.py"
echo ""
echo "  To verify which policies are active per agent:"
echo "     sudo python3 tools/sync_sca_to_opensearch.py --diagnose"
echo ""
