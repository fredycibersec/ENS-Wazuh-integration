#!/usr/bin/env python3
"""
Validate ENS Wazuh SCA policy files.
Checks YAML syntax, required fields, check ID uniqueness, and compliance tags.
"""

import re
import sys
import yaml
import argparse

REQUIRED_POLICY_FIELDS = {"id", "file", "name", "description"}
REQUIRED_CHECK_FIELDS = {"id", "title", "description", "compliance", "condition", "rules"}
VALID_CONDITIONS = {"all", "any", "none"}
VALID_ENS_LEVELS = {"Básico", "Medio", "Alto"}

# Wazuh SCA uses POSIX ERE for Windows registry rules; these PCRE shorthands are not supported.
_NON_POSIX_RE = re.compile(r'\\[dDwWsSbB]')
# Windows registry rules start with r:HK (HKLM, HKCU, HKCC, HKCR, HKU)
_WIN_REGISTRY_RULE_RE = re.compile(r'^!?r:HK', re.IGNORECASE)


def _extract_rule_regex(rule: str) -> str | None:
    """Return the regex portion of a Windows registry rule (after '-> r:' or '-> !r:')."""
    m = re.search(r'->\s*!?r:(.+)$', rule)
    return m.group(1) if m else None


def validate_check_rules(check: dict, prefix: str, errors: list) -> None:
    for rule in check.get("rules", []):
        if not _WIN_REGISTRY_RULE_RE.match(rule.lstrip()):
            continue
        regex_part = _extract_rule_regex(rule)
        if regex_part is None:
            continue
        for match in _NON_POSIX_RE.finditer(regex_part):
            errors.append(
                f"{prefix}: Non-POSIX regex shorthand '{match.group()}' in Windows registry rule "
                f"(use POSIX equivalent, e.g. [0-9] for \\d): {rule!r}"
            )


def load_policy(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def validate_policy(path: str, data: dict, errors: list, warnings: list) -> None:
    policy = data.get("policy", {})
    missing = REQUIRED_POLICY_FIELDS - set(policy.keys())
    if missing:
        errors.append(f"{path}: Missing policy fields: {missing}")

    checks = data.get("checks", [])
    if not checks:
        errors.append(f"{path}: No checks defined")
        return

    for check in checks:
        cid = check.get("id", "?")
        prefix = f"{path} [check {cid}]"

        missing_fields = REQUIRED_CHECK_FIELDS - set(check.keys())
        if missing_fields:
            errors.append(f"{prefix}: Missing fields: {missing_fields}")

        if check.get("condition") not in VALID_CONDITIONS:
            errors.append(f"{prefix}: Invalid condition '{check.get('condition')}'")

        validate_check_rules(check, prefix, errors)

        compliance = check.get("compliance", [])
        ens_controls = [c.get("ens") for c in compliance if "ens" in c]
        ens_levels = [c.get("ens_nivel") for c in compliance if "ens_nivel" in c]

        if not ens_controls:
            warnings.append(f"{prefix}: No 'ens' compliance tag defined")

        if not ens_levels:
            warnings.append(f"{prefix}: No 'ens_nivel' compliance tag defined")
        else:
            for level in ens_levels:
                if level not in VALID_ENS_LEVELS:
                    errors.append(f"{prefix}: Invalid ens_nivel '{level}'. Must be one of {VALID_ENS_LEVELS}")


def check_duplicates(files: list[str]) -> list[str]:
    seen = {}
    duplicates = []
    for path in files:
        data = load_policy(path)
        for check in data.get("checks", []):
            cid = check.get("id")
            if cid in seen:
                duplicates.append(f"Duplicate check ID {cid} in {path} (also in {seen[cid]})")
            else:
                seen[cid] = path
    return duplicates


def main():
    parser = argparse.ArgumentParser(description="Validate ENS Wazuh SCA policies")
    parser.add_argument("files", nargs="+", help="SCA YAML files to validate")
    parser.add_argument("--check-duplicates", action="store_true", help="Check for duplicate check IDs across files")
    args = parser.parse_args()

    all_errors = []
    all_warnings = []

    for path in args.files:
        try:
            data = load_policy(path)
            errors = []
            warnings = []
            validate_policy(path, data, errors, warnings)
            all_errors.extend(errors)
            all_warnings.extend(warnings)
            if not errors:
                print(f"  OK  {path} ({len(data.get('checks', []))} checks)")
        except yaml.YAMLError as e:
            all_errors.append(f"{path}: YAML parse error: {e}")
        except FileNotFoundError:
            all_errors.append(f"{path}: File not found")

    if args.check_duplicates:
        dups = check_duplicates(args.files)
        all_errors.extend(dups)

    if all_warnings:
        print("\nWarnings:")
        for w in all_warnings:
            print(f"  WARN  {w}")

    if all_errors:
        print("\nErrors:")
        for e in all_errors:
            print(f"  ERROR {e}")
        sys.exit(1)

    print(f"\nValidation passed. {len(all_warnings)} warning(s), 0 errors.")


if __name__ == "__main__":
    main()
