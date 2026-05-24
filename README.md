# ENS Wazuh Integration

[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-blue)](https://wazuh.com)
[![License](https://img.shields.io/badge/License-GPL--2.0-green)](LICENSE)
[![ENS](https://img.shields.io/badge/ENS-RD%20311%2F2022-red)](https://www.boe.es/boe/dias/2022/05/03/pdfs/BOE-A-2022-7191.pdf)

Community integration of the **Spanish National Security Framework (Esquema Nacional de Seguridad — ENS, Real Decreto 311/2022)** for [Wazuh](https://wazuh.com).

> [!NOTE]
> This is a community project maintained by a [Wazuh Ambassador](https://wazuh.com/community/ambassador-program/). It is not officially supported by Wazuh, Inc.

---
<p align="center">
  <img width="900" alt="ENS Dashboard" src="https://github.com/user-attachments/assets/6a98315f-da6b-4e54-a4aa-c07e9fd6672b" />
  <img width="900" alt="SCA-ENS Dashboard" src="https://github.com/user-attachments/assets/6ea25533-2c2f-49e0-bac5-eda1cb3d2fad" />
</p>



## What is ENS?

The **Esquema Nacional de Seguridad (ENS)** is the Spanish national cybersecurity framework, mandatory for public administrations and their technology providers. It is defined in **Real Decreto 311/2022** and structured in three compliance levels:

| Level | Description |
|-------|-------------|
| **Básico** | Baseline security measures |
| **Medio** | Intermediate controls, adds to Básico |
| **Alto** | Strictest controls, adds to Medio |

ENS covers three control families: **[org]** Organizational, **[op]** Operational, and **[mp]** Protection Measures.

---

## What this integration provides

| Component | Description |
|-----------|-------------|
| **SCA Policies** | YAML policies for Linux and Windows agents that audit system configuration against ENS controls |
| **Detection Rules** | Custom Wazuh rules tagged with ENS control references |
| **Control Mapping** | Full reference table mapping ENS controls to Wazuh checks and rules |
| **Dashboards** | OpenSearch dashboards for ENS compliance visualization |
| **API Sync Tool** | Bridge script that indexes check-level SCA data into a dedicated OpenSearch index for rich dashboards |

---

## Supported versions

- **Wazuh**: 4.4 or later (4.7+ recommended)
- **Agents**: Linux (RHEL/CentOS/Debian/Ubuntu/Kali), Windows 10/11/Server 2019+
- **OpenSearch**: 2.x (for dashboards)

---

## Installation overview

The integration has two phases:

| Phase | Script | What it does |
|-------|--------|--------------|
| **1 — Core** | `install.sh` | Installs SCA policies, detection rules, and configures the manager |
| **2 — Sync** | `install_sync.sh` | Installs the API bridge, cron job, and check-level dashboard |

---

## Phase 1 — Core installation

### Automated

```bash
git clone https://github.com/fredycibersec/ENS-Wazuh-integration.git
cd ENS-Wazuh-integration
sudo bash install.sh
```

The installer:
1. Copies SCA policies to `/var/ossec/ruleset/sca/`
2. Copies detection rules to `/var/ossec/etc/rules/`
3. Updates `ossec.conf` to enable the ENS SCA policies
4. Restarts the Wazuh manager

### Manual

#### 1. Copy SCA policies

```bash
sudo cp sca/ens_linux.yml /var/ossec/ruleset/sca/
sudo cp sca/ens_windows.yml /var/ossec/ruleset/sca/
```

#### 2. Enable SCA policies in ossec.conf

Add the following inside the `<sca>` block in `/var/ossec/etc/ossec.conf`:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
  <skip_nfs>yes</skip_nfs>
  <policies>
    <policy>ruleset/sca/ens_linux.yml</policy>
    <policy>ruleset/sca/ens_windows.yml</policy>
  </policies>
</sca>
```

#### 3. Copy detection rules

```bash
sudo cp rules/ens_detection_rules.xml /var/ossec/etc/rules/
```

#### 4. Import the summary dashboard

1. Open OpenSearch Dashboards (usually `https://<wazuh-ip>`)
2. Go to **Stack Management → Saved Objects → Import**
3. Upload `dashboards/ens_dashboard.ndjson`
4. Navigate to **Dashboards → ENS — Esquema Nacional de Seguridad**

> **Note:** The NDJSON uses the `wazuh-alerts-*` index pattern that Wazuh creates automatically.

#### 5. Restart Wazuh manager

```bash
sudo systemctl restart wazuh-manager
```

---

## Phase 2 — API Sync Tool (check-level dashboard)

Wazuh 4.x only indexes SCA **summary** events into `wazuh-alerts-*`. Individual check results (pass/fail per control) are stored in SQLite on the manager and accessible only via the Wazuh REST API. The sync tool bridges this gap by polling the API and indexing full check-level data into a dedicated `ens-sca-checks` OpenSearch index.

### Automated

```bash
sudo bash install_sync.sh
```

The installer:
1. Detects Python 3 and installs the `requests` library if missing
2. Reads credentials automatically from `wazuh-install-files.tar` (searched in `/root`, `/home/*`, `/tmp`, `/var/tmp`) — prompts interactively if not found
3. Tests connectivity to the Wazuh API and OpenSearch
4. Copies the sync script to `/opt/ENS-Wazuh-integration/tools/`
5. Runs an initial sync
6. Creates `/etc/cron.d/ens-sca-sync` (runs every 15 minutes as root)
7. Imports `ens_sca_checks_dashboard.ndjson` into OpenSearch Dashboards

If OpenSearch Dashboards runs on a non-default port:

```bash
sudo OSD_HOST=https://localhost:5601 bash install_sync.sh
```

### Manual setup

```bash
# Install dependency
pip3 install requests

# Run as root — credentials are read automatically from wazuh-install-files.tar
# if it exists in /root, /home/*, /tmp or /var/tmp
sudo python3 tools/sync_sca_to_opensearch.py --dry-run

# Or pass credentials explicitly
sudo WAZUH_USER=wazuh WAZUH_PASS='xxx' OS_USER=admin OS_PASS='xxx' \
  python3 tools/sync_sca_to_opensearch.py
```

> **Important:** Run as `root` (or with `sudo`). The `wazuh-install-files.tar` has 700 permissions and is only readable by root.

### Credentials

The script reads credentials from `wazuh-install-files.tar` automatically. The required users are:

| Variable | User | Source in tar |
|----------|------|---------------|
| `WAZUH_USER` | `wazuh` or `wazuh-wui` | `api_username:` entry |
| `WAZUH_PASS` | (generated) | `api_password:` entry |
| `OS_USER` | `admin` | `username: admin` entry |
| `OS_PASS` | (generated) | `password:` entry |

To verify what the tar contains:

```bash
sudo tar -xOf ~/wazuh-install-files.tar \
  $(sudo tar -tf ~/wazuh-install-files.tar | grep -i password)
```

### Available flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Fetch data from API but do not write to OpenSearch |
| `--diagnose` | List agents, show available SCA policies per agent, identify why 0 docs may occur |
| `--include-manager` | Also sync SCA checks from the manager itself (agent 000) |

```bash
# Diagnose why 0 documents are indexed
sudo python3 tools/sync_sca_to_opensearch.py --diagnose

# Include the manager's own SCA results
sudo python3 tools/sync_sca_to_opensearch.py --include-manager
```

### Cron job

The automated installer creates `/etc/cron.d/ens-sca-sync`. To edit the schedule or add `--include-manager`:

```bash
sudo nano /etc/cron.d/ens-sca-sync
```

Default content:

```
*/15 * * * * root python3 /opt/ENS-Wazuh-integration/tools/sync_sca_to_opensearch.py >> /var/log/ens-sca-sync.log 2>&1
```

Watch the sync log:

```bash
tail -f /var/log/ens-sca-sync.log
```

### Import the check-level dashboard

1. **Stack Management → Saved Objects → Import**
2. Upload `dashboards/ens_sca_checks_dashboard.ndjson`
3. Navigate to **Dashboards → ENS — SCA Check-Level Compliance**

Panels included:

| Panel | Description |
|-------|-------------|
| Passed checks | Total checks with result `passed` |
| Pass / Fail pie | Distribution of results |
| Results by ENS level | Stacked bar: Básico / Medio / Alto |
| Compliance by agent | Per-agent pass/fail breakdown |
| Top failing controls | ENS controls with most failures |
| Failed checks table | Full list with title, level, agent, remediation |

---

## Deploying SCA policies to agents

By default, the SCA policies run on the Wazuh manager itself. To audit remote agents, deploy the policies via **Wazuh groups** — the manager pushes the files automatically to all agents in the group.

### Automated script (recommended)

```bash
sudo bash deploy_sca_agents.sh
```

The script:
1. Reads Wazuh API credentials from `wazuh-install-files.tar` automatically
2. Queries the Wazuh API for all active agents and detects their OS
3. Creates the `ens-linux` and `ens-windows` groups if they do not exist
4. Copies the policy files to the group shared directories
5. Writes the `agent.conf` for each group
6. Assigns each agent to the correct group based on its OS

Available flags:

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would be done without making any changes |
| `--force-scan` | Trigger an immediate SCA scan on all assigned agents |
| `--no-assign` | Create groups and copy files only; skip agent assignment |

```bash
# Preview without changes
sudo bash deploy_sca_agents.sh --dry-run

# Deploy and force immediate scans
sudo bash deploy_sca_agents.sh --force-scan
```

### From the web UI

The web UI does not support uploading arbitrary files to a group — SCA policy files must be copied via the CLI. What you **can** do from the UI:

1. **Management → Groups → Add new group** — name it `ens-linux`
2. **Groups → ens-linux → Edit group configuration** — paste the `agent.conf` block (after copying the policy file via CLI)
3. **Agents → select agent → Groups → Assign group → ens-linux**

### From the command line (manual)

```bash
# Create the group
/var/ossec/bin/agent_groups -a -g ens-linux

# Copy the policy into the group's shared directory
sudo cp /var/ossec/ruleset/sca/ens_linux.yml /var/ossec/etc/shared/ens-linux/
sudo chown wazuh:wazuh /var/ossec/etc/shared/ens-linux/ens_linux.yml

# Create the group configuration
sudo tee /var/ossec/etc/shared/ens-linux/agent.conf <<'EOF'
<agent_config>
  <sca>
    <policies>
      <policy>etc/shared/ens_linux.yml</policy>
    </policies>
  </sca>
</agent_config>
EOF

# Assign an agent to the group (replace 001 with the agent ID)
/var/ossec/bin/agent_groups -a -i 001 -g ens-linux

# List agents in the group
/var/ossec/bin/agent_groups -l -g ens-linux

# Force an immediate SCA scan
/var/ossec/bin/agent_control -r -u 001
```

### For Windows agents

```bash
/var/ossec/bin/agent_groups -a -g ens-windows
sudo cp /var/ossec/ruleset/sca/ens_windows.yml /var/ossec/etc/shared/ens-windows/
sudo chown wazuh:wazuh /var/ossec/etc/shared/ens-windows/ens_windows.yml

sudo tee /var/ossec/etc/shared/ens-windows/agent.conf <<'EOF'
<agent_config>
  <sca>
    <policies>
      <policy>etc/shared/ens_windows.yml</policy>
    </policies>
  </sca>
</agent_config>
EOF

/var/ossec/bin/agent_groups -a -i <agent_id> -g ens-windows
/var/ossec/bin/agent_control -r -u <agent_id>
```

### Verify the policy reached the agent

```bash
# On the manager — check the agent received the file
ls /var/ossec/etc/shared/ens-linux/

# Check the agent's SCA log (on the agent or via manager logs)
grep -i "ens_linux" /var/ossec/logs/ossec.log | tail -10

# Confirm via diagnose mode (shows all policies per agent)
sudo python3 tools/sync_sca_to_opensearch.py --diagnose
```

The policy synchronisation typically takes 1–2 minutes. After the first scan completes, run the sync tool to index the results.

---

## Troubleshooting

### 0 documents indexed

Run the diagnose mode to identify the cause:

```bash
sudo python3 tools/sync_sca_to_opensearch.py --diagnose
```

| Symptom | Cause | Fix |
|---------|-------|-----|
| No active agents listed | No agents connected | Install and register agents |
| No SCA policies found for an agent | First scan not yet run | Force scan: `agent_control -r -u <id>` |
| ENS policies not in agent list | Policy not deployed to agent | Follow the group deployment steps above |
| Only manager (000) has ENS data | No remote agents with ENS | Add `--include-manager` flag |
| 401 Unauthorized on Wazuh API | Wrong credentials | Check `WAZUH_USER` / `WAZUH_PASS` |

### Dashboard fields missing

If panels show "Could not locate index-pattern field":

1. Wait for the first sync to complete and create the `ens-sca-checks` index
2. Refresh the index pattern: **Stack Management → Index Patterns → ens-sca-checks → ⟳**

### SCA policy skipped by Wazuh

Check the manager log for parse errors:

```bash
grep -i "ens_linux\|ens_windows\|Invalid check" /var/ossec/logs/ossec.log | tail -20
```

Run the full diagnostic script:

```bash
sudo bash tests/diagnose_sca.sh admin <opensearch-password>
```

---

## ENS Controls Coverage

### Automated (SCA + Rules)

| Family | Control | Description | Level |
|--------|---------|-------------|-------|
| op.acc | op.acc.1 | Identification | Básico |
| op.acc | op.acc.2 | Access requirements | Básico |
| op.acc | op.acc.3 | Segregation of duties | Básico |
| op.acc | op.acc.6 | Authentication (org users) | Básico |
| op.acc | op.acc.7 | Remote access | Medio |
| op.exp | op.exp.2 | Security configuration | Básico |
| op.exp | op.exp.6 | Malware protection | Básico |
| op.exp | op.exp.8 | User activity logging | Básico |
| op.exp | op.exp.10 | Log protection | Medio |
| op.mon | op.mon.1 | Intrusion detection | Básico |
| mp.com | mp.com.2 | Confidentiality | Medio |
| mp.com | mp.com.3 | Authenticity/integrity | Básico |
| mp.com | mp.com.4 | Network segregation | Básico |
| mp.eq | mp.eq.2 | Workstation lock | Básico |
| mp.info | mp.info.3 | Information encryption | Medio |
| mp.info | mp.info.9 | Backups | Básico |
| mp.s | mp.s.2 | Service protection | Básico |
| mp.s | mp.s.3 | DoS protection | Básico |
| mp.sw | mp.sw.2 | Software acceptance | Básico |

### Requires manual evidence

| Family | Control | Description |
|--------|---------|-------------|
| org.* | org.1–4 | Policies, procedures, authorizations |
| mp.if | mp.if.1–7 | Physical facilities |
| mp.per | mp.per.1–5 | Personnel management |
| mp.si | mp.si.1–5 | Physical media handling |

---

## Project structure

```
ENS-Wazuh-integration/
├── sca/
│   ├── ens_linux.yml                   # SCA policy for Linux agents
│   └── ens_windows.yml                 # SCA policy for Windows agents
├── rules/
│   └── ens_detection_rules.xml         # Custom detection rules with ENS tags
├── dashboards/
│   ├── ens_dashboard.ndjson            # Summary dashboard (wazuh-alerts-*)
│   └── ens_sca_checks_dashboard.ndjson # Check-level dashboard (ens-sca-checks)
├── tools/
│   └── sync_sca_to_opensearch.py       # Wazuh API → OpenSearch bridge
├── docs/
│   ├── controls_mapping.md             # Full ENS ↔ Wazuh mapping reference
│   └── installation_guide.md          # Detailed installation guide
├── tests/
│   ├── validate_sca.py                 # SCA policy syntax validation script
│   └── diagnose_sca.sh                 # Diagnostic script for missing compliance fields
├── install.sh                          # Phase 1: core installer
├── install_sync.sh                     # Phase 2: API sync installer
├── deploy_sca_agents.sh                # Deploy SCA policies to agents via groups
├── uninstall.sh                        # Core uninstaller
└── uninstall_sync.sh                   # Sync tool uninstaller
```

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

Areas where help is especially needed:
- Windows SCA policy checks
- Additional op.exp and mp.com checks
- OpenSearch dashboard improvements
- Translations and documentation

---

## References

- [Real Decreto 311/2022 — BOE](https://www.boe.es/boe/dias/2022/05/03/pdfs/BOE-A-2022-7191.pdf)
- [CCN-CERT ENS Portal](https://ens.ccn.cni.es)
- [Wazuh SCA Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/)
- [Wazuh Rules Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/custom-rules/)
- [Wazuh Groups Documentation](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)

---

## License

This project is licensed under the **GNU General Public License v2.0** — see [LICENSE](LICENSE) for details.

---

## Author

Maintained by **Alfredo Ramírez**, Wazuh Ambassador.
https://wazuh.com/ambassadors/alfredo-ramirez/
