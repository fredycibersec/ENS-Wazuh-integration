# Changelog

## [Unreleased]

### Added
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
