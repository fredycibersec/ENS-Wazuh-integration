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
