#!/usr/bin/env python3
"""
ENS SCA → OpenSearch bridge
Polls the Wazuh API for ENS SCA check results and indexes them into
a custom OpenSearch index (ens-sca-checks) for rich dashboard visualization.

Credentials are loaded automatically from wazuh-install-files.tar if found
in common locations (/root, /home/*, /tmp, /var/tmp). You can also set them
via environment variables (env vars take priority over the tar):

    export WAZUH_USER=wazuh-wui   # default
    export WAZUH_PASS=<password>
    export OS_USER=admin           # default
    export OS_PASS=<password>

Optional overrides (defaults shown):
    export WAZUH_HOST=https://localhost:55000
    export OS_HOST=https://localhost:9200
    export OS_INDEX=ens-sca-checks
    export ENS_POLICIES=ens_linux,ens_windows

Usage:
    python3 tools/sync_sca_to_opensearch.py [--dry-run] [--diagnose] [--include-manager]
"""

import glob
import os
import sys
import json
import logging
import argparse
import tarfile
from datetime import datetime, timezone

try:
    import requests
    import urllib3
except ImportError:
    sys.exit("Missing dependency: pip install requests")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Credential auto-detection from wazuh-install-files.tar ────────────────────

# Base dirs to search — same set as install_sync.sh uses with find -maxdepth 2
_TAR_BASE_DIRS = ["/root", "/home", "/tmp", "/var/tmp"]
TAR_INTERNAL_PATHS = [
    "wazuh-install-files/wazuh-passwords.txt",
    "wazuh-passwords.txt",
]


def _read_passwords_from_tar(tar_path):
    """Return the text content of wazuh-passwords.txt inside the tar, or None."""
    try:
        with tarfile.open(tar_path, "r:*") as tf:
            for internal in TAR_INTERNAL_PATHS:
                try:
                    member = tf.getmember(internal)
                    return tf.extractfile(member).read().decode("utf-8", errors="replace")
                except KeyError:
                    continue
    except Exception:
        pass
    return None


def _extract_password(content, username):
    """
    Parse a password for *username* from wazuh-passwords.txt.

    Handles Wazuh 4.x installer formats line by line:
      api_username: 'X'  →  api_password: 'Y'
      username: "X"      →  password: "Y"
      username: X        →  password: Y
    """
    lines = content.splitlines()
    user_keys = ("api_username:", "username:")
    pass_keys = ("api_password:", "password:")

    for i, line in enumerate(lines):
        stripped = line.strip()
        # Find lines that declare this username
        for ukey in user_keys:
            if not stripped.startswith(ukey):
                continue
            value = stripped[len(ukey):].strip().strip("\"'")
            if value != username:
                continue
            # Found the username line — look for the password within the next 3 lines
            for j in range(i + 1, min(i + 4, len(lines))):
                pline = lines[j].strip()
                for pkey in pass_keys:
                    if pline.startswith(pkey):
                        return pline[len(pkey):].strip().strip("\"'")

    return None


def _find_tar():
    # Mirror bash: find <dir> -maxdepth 2 -name wazuh-install-files.tar
    # Glob patterns cover depth 0 (dir itself) and depth 1 (one subdir)
    for base in _TAR_BASE_DIRS:
        for pattern in (
            os.path.join(base, "wazuh-install-files.tar"),
            os.path.join(base, "*", "wazuh-install-files.tar"),
        ):
            matches = glob.glob(pattern)
            if matches:
                return matches[0]
    return None


def load_credentials_from_tar():
    """
    Try to read WAZUH_PASS and OS_PASS from wazuh-install-files.tar.
    Returns a dict with the keys found; missing keys are absent.
    """
    tar_path = _find_tar()
    if not tar_path:
        return {}

    # File found — check we can actually read it
    if not os.access(tar_path, os.R_OK):
        log.warning("Found %s but cannot read it (permission denied)", tar_path)
        log.warning("Run the script as root:  sudo python3 %s", sys.argv[0])
        return {}

    content = _read_passwords_from_tar(tar_path)
    if not content:
        log.warning("Found %s but could not extract wazuh-passwords.txt from it", tar_path)
        return {}

    log.info("Reading credentials from %s", tar_path)
    creds = {}

    # Try wazuh-wui first (standard API UI user), fall back to wazuh
    for api_user in ("wazuh-wui", "wazuh"):
        wazuh_pass = _extract_password(content, api_user)
        if wazuh_pass:
            creds["WAZUH_PASS"] = wazuh_pass
            creds["WAZUH_USER"] = api_user
            log.info("  Wazuh API user/password: %s / %s***  (from tar)",
                     api_user, wazuh_pass[:6])
            break
    else:
        log.warning("  Wazuh API password: not found in tar — set WAZUH_PASS env var")

    admin_pass = _extract_password(content, "admin")
    if admin_pass:
        creds["OS_PASS"] = admin_pass
        log.info("  OpenSearch admin password: %s***  (from tar)", admin_pass[:6])
    else:
        log.warning("  OpenSearch admin password: not found in tar — set OS_PASS env var")

    return creds


# ── Configuration ──────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("ens-sync")

# Warn early if not root — the install tar is typically owned by root (700)
if os.geteuid() != 0 and not any(os.getenv(v) for v in ("WAZUH_PASS", "OS_PASS")):
    log.warning("Not running as root — wazuh-install-files.tar may not be readable")
    log.warning("Run with:  sudo python3 %s", sys.argv[0])
    log.warning("Or set credentials manually:  export WAZUH_PASS=xxx OS_PASS=xxx")

# Load from tar first, then let env vars override
_tar_creds = load_credentials_from_tar()

WAZUH_HOST   = os.getenv("WAZUH_HOST",   "https://localhost:55000")
WAZUH_USER   = os.getenv("WAZUH_USER",   _tar_creds.get("WAZUH_USER", "wazuh-wui"))
WAZUH_PASS   = os.getenv("WAZUH_PASS",   _tar_creds.get("WAZUH_PASS", ""))
OS_HOST      = os.getenv("OS_HOST",      "https://localhost:9200")
OS_USER      = os.getenv("OS_USER",      "admin")
OS_PASS      = os.getenv("OS_PASS",      _tar_creds.get("OS_PASS", ""))
OS_INDEX     = os.getenv("OS_INDEX",     "ens-sca-checks")
ENS_POLICIES = os.getenv("ENS_POLICIES", "ens_linux,ens_windows").split(",")

log = logging.getLogger("ens-sync")

# ── Wazuh API helpers ──────────────────────────────────────────────────────────

def wazuh_token():
    r = requests.post(
        f"{WAZUH_HOST}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False, timeout=10,
    )
    if r.status_code == 401:
        log.error("Wazuh API authentication failed (401 Unauthorized)")
        log.error("  Host: %s", WAZUH_HOST)
        log.error("  User: %s", WAZUH_USER)
        log.error("  Pass: %s***  (first 3 chars)", WAZUH_PASS[:3] if WAZUH_PASS else "(empty)")
        log.error("Override with:  export WAZUH_USER=<user>  export WAZUH_PASS=<password>")
        sys.exit(1)
    r.raise_for_status()
    return r.json()["data"]["token"]


def wazuh_get(token, path, params=None):
    """Fetch all items from a paginated Wazuh API endpoint."""
    headers = {"Authorization": f"Bearer {token}"}
    items, offset, limit = [], 0, 500
    while True:
        p = {"limit": limit, "offset": offset, **(params or {})}
        r = requests.get(f"{WAZUH_HOST}{path}", headers=headers,
                         params=p, verify=False, timeout=30)
        r.raise_for_status()
        body = r.json()
        if body.get("error", 0) != 0:
            raise RuntimeError(f"Wazuh API error on {path}: {body}")
        data  = body["data"]
        items.extend(data["affected_items"])
        if len(items) >= data["total_affected_items"]:
            break
        offset += limit
    return items


def get_active_agents(token, include_manager=False):
    agents = wazuh_get(token, "/agents", {"status": "active"})
    if not include_manager:
        agents = [a for a in agents if a["id"] != "000"]
    return agents


def get_sca_policies(token, agent_id):
    """Return the list of SCA policies available for an agent."""
    try:
        return wazuh_get(token, f"/sca/{agent_id}")
    except Exception as exc:
        log.warning("agent=%s — cannot fetch SCA policies: %s", agent_id, exc)
        return []


def get_sca_checks(token, agent_id, policy_id):
    try:
        return wazuh_get(token, f"/sca/{agent_id}/checks/{policy_id}")
    except Exception as exc:
        log.warning("agent=%s policy=%s — %s", agent_id, policy_id, exc)
        return []

# ── Document builder ───────────────────────────────────────────────────────────

def parse_compliance(raw):
    """Convert Wazuh API compliance list to a flat dict."""
    result = {}
    for item in raw or []:
        if isinstance(item, dict):
            if "key" in item and "value" in item:
                result[item["key"]] = item["value"]
            else:
                result.update(item)
    return result


def build_doc(agent, policy_id, check, ts):
    compliance = parse_compliance(check.get("compliance", []))
    return {
        "@timestamp": ts,
        "agent": {
            "id":       agent["id"],
            "name":     agent.get("name", agent["id"]),
            "ip":       agent.get("ip", ""),
            "os":       agent.get("os", {}).get("platform", ""),
            "version":  agent.get("version", ""),
        },
        "ens": {
            "policy_id": policy_id,
            "check": {
                "id":          check.get("id"),
                "title":       check.get("title", ""),
                "result":      check.get("result", ""),
                "description": check.get("description", ""),
                "rationale":   check.get("rationale", ""),
                "remediation": check.get("remediation", ""),
                "compliance":  compliance,
            },
        },
    }

# ── OpenSearch helpers ─────────────────────────────────────────────────────────

INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "agent": {
                "properties": {
                    "id":      {"type": "keyword"},
                    "name":    {"type": "keyword"},
                    "ip":      {"type": "keyword"},
                    "os":      {"type": "keyword"},
                    "version": {"type": "keyword"},
                }
            },
            "ens": {
                "properties": {
                    "policy_id": {"type": "keyword"},
                    "check": {
                        "properties": {
                            "id":          {"type": "integer"},
                            "title":       {"type": "keyword"},
                            "result":      {"type": "keyword"},
                            "description": {"type": "text"},
                            "rationale":   {"type": "text"},
                            "remediation": {"type": "text"},
                            "compliance": {
                                "properties": {
                                    "ens":       {"type": "keyword"},
                                    "ens_nivel": {"type": "keyword"},
                                }
                            },
                        }
                    },
                }
            },
        }
    }
}


def ensure_index():
    r = requests.put(
        f"{OS_HOST}/{OS_INDEX}",
        auth=(OS_USER, OS_PASS),
        json=INDEX_MAPPING,
        verify=False, timeout=10,
    )
    if r.status_code == 400 and "already_exists" in r.text:
        log.debug("Index %s already exists", OS_INDEX)
    elif r.status_code not in (200, 201):
        r.raise_for_status()
    else:
        log.info("Index %s created", OS_INDEX)


def bulk_index(docs):
    if not docs:
        return 0
    lines = []
    for doc_id, doc in docs:
        lines.append(json.dumps({"index": {"_index": OS_INDEX, "_id": doc_id}}))
        lines.append(json.dumps(doc, ensure_ascii=False))
    body = "\n".join(lines) + "\n"
    r = requests.post(
        f"{OS_HOST}/_bulk",
        auth=(OS_USER, OS_PASS),
        headers={"Content-Type": "application/x-ndjson"},
        data=body.encode("utf-8"),
        verify=False, timeout=60,
    )
    r.raise_for_status()
    resp  = r.json()
    ok    = sum(1 for i in resp.get("items", []) if "error" not in i.get("index", {}))
    errs  = [i["index"]["error"] for i in resp.get("items", []) if "error" in i.get("index", {})]
    if errs:
        log.error("Bulk errors (first 3): %s", errs[:3])
    return ok

# ── Main ───────────────────────────────────────────────────────────────────────

def check_env():
    missing = []
    if not WAZUH_PASS:
        missing.append("WAZUH_PASS")
    if not OS_PASS:
        missing.append("OS_PASS")
    if missing:
        log.error("Missing credentials: %s", ", ".join(missing))
        log.error("Options:")
        log.error("  1. Place wazuh-install-files.tar in /root, /home/*, /tmp, or /var/tmp")
        log.error("  2. Set env vars:  export %s=<password>", " ".join(missing))
        sys.exit(1)


def diagnose(token):
    """Print a detailed report to help identify why 0 documents are indexed."""
    print("\n── Diagnose ─────────────────────────────────────────────────────────")

    # All agents including manager
    all_agents = wazuh_get(token, "/agents", {"status": "active"})
    print(f"\nActive agents (including manager): {len(all_agents)}")
    for a in all_agents:
        print(f"  id={a['id']:>3}  name={a.get('name','?'):<24} "
              f"os={a.get('os',{}).get('platform','?'):<10} "
              f"version={a.get('version','?')}")

    agents_to_check = all_agents  # include 000 for diagnosis
    if not agents_to_check:
        print("\n  ✗ No active agents found — nothing to sync")
        return

    print(f"\nSearching for ENS policies: {ENS_POLICIES}")
    print("\nSCA policies available per agent:")
    found_any = False
    for agent in agents_to_check:
        aid  = agent["id"]
        name = agent.get("name", aid)
        policies = get_sca_policies(token, aid)
        if not policies:
            print(f"  agent={name} ({aid}) — no SCA policies found (scan not yet run?)")
            continue
        for p in policies:
            pid   = p.get("policy_id", "?")
            score = p.get("score", "?")
            total = p.get("total_checks", "?")
            match = "✔ MATCH" if pid in ENS_POLICIES else "  (not ENS)"
            print(f"  agent={name:<24} policy_id={pid:<20} score={score}  checks={total}  {match}")
            if pid in ENS_POLICIES:
                found_any = True

    if not found_any:
        print("\n  ✗ No ENS policies found on any agent.")
        print("    Possible causes:")
        print("    1. The first SCA scan has not completed yet — wait or force one:")
        print("       /var/ossec/bin/agent_control -r -u <agent_id>")
        print("    2. The ENS policy files are not installed on the manager:")
        print("       sudo bash install.sh")
        print("    3. The ossec.conf <sca> block does not reference the ENS policies:")
        print("       grep ens /var/ossec/etc/ossec.conf")
        print("    4. Agent 000 (manager) runs SCA but is excluded from normal sync.")
        print("       Re-run with --include-manager to also index manager checks.")
    else:
        print("\n  ✔ ENS policies found. If indexed=0, try --include-manager")
        print("    or check that the agent is active and has completed at least one scan.")

    print("─────────────────────────────────────────────────────────────────────\n")


def main(dry_run=False, diagnose_mode=False, include_manager=False):
    check_env()

    token = wazuh_token()

    if diagnose_mode:
        diagnose(token)
        return

    log.info("Starting ENS SCA → OpenSearch sync (dry_run=%s)", dry_run)

    if not dry_run:
        ensure_index()

    agents = get_active_agents(token, include_manager=include_manager)
    log.info("Active agents: %d", len(agents))

    if not agents:
        log.warning("No active agents found. Run with --diagnose for details.")

    ts   = datetime.now(timezone.utc).isoformat()
    docs = []
    for agent in agents:
        for policy_id in ENS_POLICIES:
            checks = get_sca_checks(token, agent["id"], policy_id)
            if not checks:
                continue
            for check in checks:
                doc    = build_doc(agent, policy_id, check, ts)
                doc_id = f"{agent['id']}_{policy_id}_{check['id']}"
                docs.append((doc_id, doc))
            log.info("agent=%-20s policy=%-12s checks=%d",
                     agent.get("name", agent["id"]), policy_id, len(checks))

    if not docs:
        log.warning("0 documents built — run with --diagnose to identify the cause")

    if dry_run:
        log.info("DRY RUN — %d documents built, nothing indexed", len(docs))
        if docs:
            log.info("Sample document:\n%s",
                     json.dumps(docs[0][1], indent=2, ensure_ascii=False))
        return

    indexed = bulk_index(docs)
    log.info("Done — indexed %d/%d documents into %s", indexed, len(docs), OS_INDEX)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ENS SCA → OpenSearch bridge")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch data but do not write to OpenSearch")
    parser.add_argument("--diagnose", action="store_true",
                        help="Show agents, available SCA policies, and why 0 docs may occur")
    parser.add_argument("--include-manager", action="store_true",
                        help="Also sync SCA checks from the manager (agent 000)")
    args = parser.parse_args()
    main(dry_run=args.dry_run, diagnose_mode=args.diagnose,
         include_manager=args.include_manager)
