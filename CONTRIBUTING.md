# Contributing to ENS Wazuh Integration

Thank you for your interest in contributing. This project maps the Spanish National Security Framework (ENS, Real Decreto 311/2022) to Wazuh checks and detection rules. Contributions that improve coverage, accuracy, or usability are very welcome.

---

## Table of contents

1. [Reporting issues](#reporting-issues)
2. [Development setup](#development-setup)
3. [Contributing SCA checks](#contributing-sca-checks)
4. [Contributing detection rules](#contributing-detection-rules)
5. [Contributing to the dashboard](#contributing-to-the-dashboard)
6. [Updating the controls mapping](#updating-the-controls-mapping)
7. [Pull request process](#pull-request-process)

---

## Reporting issues

Use [GitHub Issues](https://github.com/fredycibersec/ENS-Wazuh-integration/issues) to report bugs or suggest improvements. Please include:

- Wazuh version (`/var/ossec/bin/wazuh-control info`)
- OS and distribution of the affected agent
- The full error message or unexpected behaviour
- Steps to reproduce

---

## Development setup

No special tooling is required. To validate your changes locally before opening a PR:

```bash
# Install the YAML parser
pip install pyyaml

# Validate both SCA policies
python3 tests/validate_sca.py sca/ens_linux.yml sca/ens_windows.yml
```

The validator checks:
- YAML syntax
- Required fields (`id`, `title`, `description`, `compliance`, `condition`, `rules`)
- Check ID uniqueness across both files
- Valid ENS levels (`Básico`, `Medio`, `Alto`)
- Presence of `ens` and `ens_nivel` compliance tags

---

## Contributing SCA checks

### Check ID ranges

IDs are allocated by ENS control family. Use the next available ID within the correct range:

| ENS family | ID range      |
|------------|---------------|
| op.acc     | 30001 – 30099 |
| op.exp     | 30100 – 30199 |
| op.mon     | 30200 – 30299 |
| mp.com     | 30300 – 30399 |
| mp.eq      | 30400 – 30499 |
| mp.info    | 30500 – 30599 |
| mp.s       | 30600 – 30699 |
| mp.sw      | 30700 – 30799 |

New families not listed above: open an issue first to agree on a range.

### Required structure

Every check must include the `ens` and `ens_nivel` compliance tags. Example:

```yaml
- id: 30036
  title: "Ensure SSH MaxAuthTries is set to 4 or less [op.acc.6] [Básico]"
  description: "Limit the number of authentication attempts per connection."
  rationale: "Reduces exposure to brute-force attacks. Required by ENS op.acc.6."
  remediation: "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config and restart sshd."
  compliance:
    - ens: "op.acc.6"
    - ens_nivel: "Básico"
  condition: all
  rules:
    - 'f:$sshd_config -> r:^\s*MaxAuthTries\s+[1-4]\s*$'
```

**Title format:** `"<description> [<ens_control>] [<level>]"` — the tags in brackets make the check self-describing in the Wazuh UI.

**ENS level values** (case-sensitive): `Básico`, `Medio`, `Alto`.

### Guidelines

- One check per configuration item. Prefer narrow, actionable checks over broad ones.
- `rationale` must reference the ENS control explicitly.
- `remediation` must give a concrete, copy-pasteable fix.
- Test the check against a real agent before submitting. Include a brief note in the PR description on how it was tested.
- Windows checks go in `ens_windows.yml` (ID range same as Linux for the same control family).

---

## Contributing detection rules

Detection rules live in `rules/ens_detection_rules.xml` and follow the standard [Wazuh rules format](https://documentation.wazuh.com/current/user-manual/ruleset/custom-rules/).

### Rule ID ranges

| ENS family | ID range        |
|------------|-----------------|
| op.acc     | 100200 – 100299 |
| op.exp     | 100300 – 100399 |
| op.mon     | 100400 – 100499 |
| mp.com     | 100500 – 100599 |
| mp.s       | 100600 – 100699 |

### Required tags

Every rule must carry the `ENS_` group tag and the specific control tag:

```xml
<rule id="100205" level="10">
  <if_group>authentication_failed</if_group>
  <match>Failed password</match>
  <description>ENS op.acc.6: Multiple failed SSH authentication attempts</description>
  <group>ENS_op_acc,ENS_op_acc_6,authentication_failed,</group>
</rule>
```

**Group naming convention:**
- Family group: `ENS_<family>` (e.g. `ENS_op_acc`)
- Control group: `ENS_<family>_<control>` (e.g. `ENS_op_acc_6`)

Both groups must be present. The `ENS_*` prefix is what the dashboard uses to filter alerts.

---

## Contributing to the dashboard

The dashboard is exported as `dashboards/ens_dashboard.ndjson` (OpenSearch saved objects).

To modify it:
1. Import the current `ens_dashboard.ndjson` into your OpenSearch Dashboards instance.
2. Make your changes in the UI.
3. Export the updated objects: **Stack Management → Saved Objects → Export**.
4. Select all ENS objects and export as NDJSON.
5. Before committing, run the following to strip the `migrationVersion` field (causes import errors on older versions):

```bash
python3 - <<'EOF'
import json
with open('dashboards/ens_dashboard.ndjson') as f:
    lines = [l.strip() for l in f if l.strip()]
out = []
for line in lines:
    obj = json.loads(line)
    obj.pop('migrationVersion', None)
    out.append(json.dumps(obj, ensure_ascii=False))
with open('dashboards/ens_dashboard.ndjson', 'w') as f:
    f.write('\n'.join(out) + '\n')
print(f"Processed {len(out)} objects.")
EOF
```

Any new visualization that references ENS compliance fields (`data.sca.check.compliance.ens`, `data.sca.check.compliance.ens_nivel`, etc.) should also be added to the `fields` list in the `index-pattern` object within the ndjson.

---

## Updating the controls mapping

`docs/controls_mapping.md` is the authoritative reference table. When you add checks or rules that cover a new ENS control, update the table accordingly:

- Add the SCA check IDs to the **SCA Check IDs** column.
- Add the rule IDs to the **Rule IDs** column.
- If a control was previously listed as manual-only, move it to the automated section.

---

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Make your changes following the conventions above.
3. Run `python3 tests/validate_sca.py sca/ens_linux.yml sca/ens_windows.yml` and fix any errors.
4. Update `docs/controls_mapping.md` if your change affects ENS control coverage.
5. Add a brief entry to `CHANGELOG.md` under `[Unreleased]`.
6. Open a PR with a clear description of:
   - Which ENS control(s) are affected
   - What was added or changed and why
   - How the change was tested

PRs that fail the SCA validator or that are missing compliance tags will be asked to fix those before merging.

---

## Security

Please do not open a public issue for a security vulnerability (credential
handling, a check/rule that could report false compliance, etc.) — see
[SECURITY.md](SECURITY.md).

## Questions

Open a [GitHub Discussion](https://github.com/fredycibersec/ENS-Wazuh-integration/discussions) for questions that are not bug reports or feature requests.
