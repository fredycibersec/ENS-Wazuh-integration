# ENS Wazuh Integration

[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-blue)](https://wazuh.com)
[![License](https://img.shields.io/badge/License-GPL--2.0-green)](LICENSE)
[![ENS](https://img.shields.io/badge/ENS-RD%20311%2F2022-red)](https://www.boe.es/boe/dias/2022/05/03/pdfs/BOE-A-2022-7191.pdf)

Community integration of the **Spanish National Security Framework (Esquema Nacional de Seguridad — ENS, Real Decreto 311/2022)** for [Wazuh](https://wazuh.com).

> [!NOTE]
> This is a community project maintained by a [Wazuh Ambassador](https://wazuh.com/community/ambassador-program/). It is not officially supported by Wazuh, Inc.

---

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

---

## Supported versions

- **Wazuh**: 4.4 or later (4.7+ recommended)
- **Agents**: Linux (RHEL/CentOS/Debian/Ubuntu), Windows 10/11/Server 2019+
- **OpenSearch**: 2.x (for dashboards)

---

## Quick start

```bash
git clone https://github.com/fredycibersec/ENS-Wazuh-integration.git
cd ENS-Wazuh-integration
sudo bash install.sh
```

The installer will:
1. Copy SCA policies to `/var/ossec/ruleset/sca/`
2. Copy detection rules to `/var/ossec/etc/rules/`
3. Update `ossec.conf` to enable the new SCA policies
4. Restart the Wazuh manager

---

## Manual installation

### 1. Copy SCA policies

```bash
sudo cp sca/ens_linux.yml /var/ossec/ruleset/sca/
sudo cp sca/ens_windows.yml /var/ossec/ruleset/sca/
```

### 2. Enable SCA policies in ossec.conf

Add the following inside the `<sca>` block in `/var/ossec/etc/ossec.conf`:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
  <skip_nfs>yes</skip_nfs>
  <policies>
    <policy>etc/shared/ens_linux.yml</policy>
    <policy>etc/shared/ens_windows.yml</policy>
  </policies>
</sca>
```

### 3. Copy detection rules

```bash
sudo cp rules/ens_detection_rules.xml /var/ossec/etc/rules/
```

### 4. Import the dashboard into OpenSearch

1. Open OpenSearch Dashboards (usually at `https://<wazuh-ip>`)
2. Go to **Stack Management → Saved Objects → Import**
3. Upload `dashboards/ens_dashboard.ndjson`
4. Navigate to **Dashboards → ENS — Esquema Nacional de Seguridad**

> **Note:** The NDJSON does not include an index pattern — it uses the `wazuh-alerts-*` pattern that Wazuh creates automatically. If your installation uses a different index pattern name, find and replace `wazuh-alerts-*` in the NDJSON before importing.

### 5. Restart Wazuh manager

```bash
sudo systemctl restart wazuh-manager
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
│   ├── ens_linux.yml          # SCA policy for Linux agents
│   └── ens_windows.yml        # SCA policy for Windows agents
├── rules/
│   └── ens_detection_rules.xml # Custom detection rules with ENS tags
├── dashboards/
│   └── ens_dashboard.ndjson   # OpenSearch dashboard (import via UI)
├── docs/
│   ├── controls_mapping.md    # Full ENS ↔ Wazuh mapping reference
│   └── installation_guide.md  # Detailed installation guide
├── tests/
│   └── validate_sca.py        # SCA policy syntax validation script
├── install.sh                 # Automated installer
└── uninstall.sh               # Uninstaller
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

---

## License

This project is licensed under the **GNU General Public License v2.0** — see [LICENSE](LICENSE) for details.

---

## Author

Maintained by **Alfredo Ramírez**, Wazuh Ambassador.
https://wazuh.com/ambassadors/alfredo-ramirez/
