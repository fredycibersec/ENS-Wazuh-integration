# Changelog

## [Unreleased]

### Added
- `docs/iso27001_mapping.md`: compatibility note documenting that Wazuh's own native ISO 27001 module (`wazuh-dashboard-plugins#8286`) uses ISO/IEC 27001:2013 numbering internally, while this project uses 2022 — flagged so the two don't get confused if run side by side.
- `rules/ens_detection_rules.xml`: each `ISO27001_<control>` group is now paired with a lowercase `iso_27001_<control>` token, matching the naming convention Wazuh's own bundled ruleset uses for other frameworks (`pci_dss_11.4`, `gdpr_IV_35.7.d`, `tsc_CC6.1`, ...). Purely additive, low-cost hedge in case a future Wazuh dashboard release enriches compliance fields from that pattern — not confirmed to have any effect today.

### Fixed
- Removed 6 pre-existing panels from `ens_dashboard.ndjson` (`ens-viz-by-level`, `ens-viz-top-failing`, `ens-viz-sca-by-family`, `ens-viz-compliance-pct-bar`, `ens-viz-control-detail-table`, `ens-viz-agent-control-table`) that queried `data.sca.type: check` against `wazuh-alerts-*`. Wazuh only writes an individual check event there on the first scan or on a pass/fail state change — never a full snapshot — so these panels showed sparse, inconsistent data depending on the selected time range (regression from an earlier fix in this same history; see commit `6206583`). The main dashboard now only uses `data.sca.type: summary` and detection-rule alerts, both of which Wazuh indexes reliably.
- Per-control compliance detail (for both ENS and the new ISO 27001:2022 tagging) is now exclusively in `ens_sca_checks_dashboard.ndjson` (Phase 2), which is fed a full snapshot on every run by `tools/sync_sca_to_opensearch.py` and does not have the sparsity problem above.
- `tools/sync_sca_to_opensearch.py`: added `iso_27001` to the `ens-sca-checks` index mapping as `keyword`.
- `tests/validate_sca.py`: warns if a check is missing the `iso_27001` compliance tag.

### Added
- ENS ↔ ISO/IEC 27001:2022 controls mapping (`docs/iso27001_mapping.md`), covering both automated and manual-evidence ENS controls
- `iso_27001` compliance tag added to all 96 SCA checks (`ens_linux.yml`, `ens_windows.yml`, `ens_windows_remote.yml`), alongside the existing `ens`/`ens_nivel` tags
- `ISO27001_<control>` groups added to all 25 tagged detection rules in `ens_detection_rules.xml`, alongside the existing `ENS_<control>` groups
- `ens_sca_checks_dashboard.ndjson` (Phase 2 check-level dashboard): ENS and ISO 27001:2022 compliance % by control, per-control detail table, per-agent drill-down for both frameworks, and an ENS↔ISO 27001 crosswalk table validated against live check data
- Initial SCA policy for Linux (`ens_linux.yml`) with 40+ checks covering op.acc, op.exp, op.mon, mp.com, mp.eq, mp.info, mp.s, mp.sw
- Initial SCA policy for Windows (`ens_windows.yml`) with baseline checks
- Detection rules (`ens_detection_rules.xml`) mapping existing Wazuh events to ENS controls
- Automated installer and uninstaller scripts
- Full ENS ↔ Wazuh controls mapping reference (`docs/controls_mapping.md`)
- SCA policy validation script (`tests/validate_sca.py`)
- GitHub Actions CI workflow for syntax validation
- **20 new SCA checks** across Linux and Windows (see breakdown below)
- **Remote/agentless Windows mode** (`sca/ens_windows_remote.yml` + `tools/collect_registry.py`):
  - Workaround for Wazuh SCA engine regression in 4.14.x that rejects `r:HKLM\...` rules on Linux managers (tracked upstream at [wazuh/wazuh#28979](https://github.com/wazuh/wazuh/issues/28979))
  - Covers the same 9 ENS checks (IDs 31010–31700) using `f:` rules against a local registry snapshot
  - Collector script supports WinRM (primary) and SSH (fallback) with single-host and batch modes
  - Policy is skipped silently if no snapshot file is present — no false positives

#### Linux new checks (Básico unless noted)
- 30005/30006: `/etc/shadow` and `/etc/passwd` permissions — `op.acc.1`
- 30014: Password complexity via `pam_pwquality` (minlen, minclass) — `op.acc.2`
- 30022: Default `umask` ≥ 027 — `op.acc.3`
- 30042: SSH `AllowAgentForwarding no` — `op.acc.7` Medio
- 30106: `/tmp` mounted with `noexec,nosuid,nodev` — `op.exp.2`
- 30107: `kernel.yama.ptrace_scope` ≥ 1 — `op.exp.2`
- 30108: `kernel.dmesg_restrict = 1` — `op.exp.2` Medio
- 30126: NTP/Chrony/systemd-timesyncd active — `op.exp.8`
- 30323: Reverse path filtering (`rp_filter = 1`) — `mp.com.4`
- 30324: ICMP broadcast ignored — `mp.com.4`
- 30325: Martian packet logging — `mp.com.4`
- 30602: FTP server not installed — `mp.s.2`

#### Windows new checks (Básico unless noted) — native + remote mode
- 31032: NLA required for RDP — `op.acc.6`
- 31033: WDigest authentication disabled — `op.acc.6`
- 31034: UAC prompts for consent/credentials — `op.acc.3`
- 31102: SMBv1 protocol disabled — `op.exp.2`
- 31121: PowerShell Script Block Logging enabled — `op.exp.8`
- 31200: Windows Time service syncs from valid source — `op.exp.8`
- 31035: LSASS runs as Protected Process Light — `op.acc.6` Medio
- 31036: Virtualization Based Security enabled — `op.acc.6` Medio
- 31302: RDP uses High or FIPS encryption — `mp.com.2` Medio

### Fixed
- `ens_windows.yml` check 31010: replaced non-POSIX regex shorthands (`\d`, `{n,}`) with POSIX-compliant equivalents supported by Wazuh's OS_Regex engine
- `ens_linux.yml` checks 30010, 30013: same class of POSIX regex fix
