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
- **Remote/agentless Windows mode** (`sca/ens_windows_remote.yml` + `tools/collect_registry.py`):
  - Workaround for Wazuh SCA engine regression in 4.14.x that rejects `r:HKLM\...` rules on Linux managers (tracked upstream at [wazuh/wazuh#28979](https://github.com/wazuh/wazuh/issues/28979))
  - Covers the same 9 ENS checks (IDs 31010–31700) using `f:` rules against a local registry snapshot
  - Collector script supports WinRM (primary) and SSH (fallback) with single-host and batch modes
  - Policy is skipped silently if no snapshot file is present — no false positives

### Fixed
- `ens_windows.yml` check 31010: replaced non-POSIX regex shorthands (`\d`, `{n,}`) with POSIX-compliant equivalents supported by Wazuh's OS_Regex engine
- `ens_linux.yml` checks 30010, 30013: same class of POSIX regex fix
