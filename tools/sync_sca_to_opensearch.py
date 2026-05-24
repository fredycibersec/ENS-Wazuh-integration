#!/usr/bin/env python3
"""
ENS SCA → OpenSearch bridge
Polls the Wazuh API for ENS SCA check results and indexes them into
a custom OpenSearch index (ens-sca-checks) for rich dashboard visualization.

Credentials are read from environment variables. Set them before running:

    export WAZUH_USER=wazuh-wui
    export WAZUH_PASS=<password>
    export OS_USER=admin
    export OS_PASS=<password>

Optional overrides (defaults shown):
    export WAZUH_HOST=https://localhost:55000
    export OS_HOST=https://localhost:9200
    export OS_INDEX=ens-sca-checks
    export ENS_POLICIES=ens_linux,ens_windows

Usage:
    python3 tools/sync_sca_to_opensearch.py [--dry-run]
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime, timezone

try:
    import requests
    import urllib3
except ImportError:
    sys.exit("Missing dependency: pip install requests")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ──────────────────────────────────────────────────────────────

WAZUH_HOST   = os.getenv("WAZUH_HOST",   "https://localhost:55000")
WAZUH_USER   = os.getenv("WAZUH_USER",   "wazuh-wui")
WAZUH_PASS   = os.getenv("WAZUH_PASS",   "")
OS_HOST      = os.getenv("OS_HOST",      "https://localhost:9200")
OS_USER      = os.getenv("OS_USER",      "")
OS_PASS      = os.getenv("OS_PASS",      "")
OS_INDEX     = os.getenv("OS_INDEX",     "ens-sca-checks")
ENS_POLICIES = os.getenv("ENS_POLICIES", "ens_linux,ens_windows").split(",")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("ens-sync")

# ── Wazuh API helpers ──────────────────────────────────────────────────────────

def wazuh_token():
    r = requests.post(
        f"{WAZUH_HOST}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False, timeout=10,
    )
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


def get_active_agents(token):
    agents = wazuh_get(token, "/agents", {"status": "active"})
    return [a for a in agents if a["id"] != "000"]


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
    missing = [v for v in ("WAZUH_PASS", "OS_USER", "OS_PASS") if not os.getenv(v)]
    if missing:
        log.error("Missing required env vars: %s", ", ".join(missing))
        log.error("See the script header for usage.")
        sys.exit(1)


def main(dry_run=False):
    check_env()
    log.info("Starting ENS SCA → OpenSearch sync (dry_run=%s)", dry_run)

    if not dry_run:
        ensure_index()

    token  = wazuh_token()
    agents = get_active_agents(token)
    log.info("Active agents: %d", len(agents))

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
    args = parser.parse_args()
    main(dry_run=args.dry_run)
