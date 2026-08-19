# Security Policy

## Reporting a vulnerability

If you find a security issue in this project (e.g. a credential-handling
problem in `tools/sync_sca_to_opensearch.py`, a way an SCA check or
detection rule could be manipulated to report false compliance, or an
installer script doing something unsafe to `ossec.conf`), please **do not
open a public GitHub issue**. Instead, use GitHub's
[private vulnerability reporting](https://github.com/fredycibersec/ENS-Wazuh-integration/security/advisories/new)
for this repository, or contact the maintainer directly.

Please include:
- A description of the issue and its impact
- Steps to reproduce
- The affected file(s) and, if relevant, the Wazuh/OpenSearch version involved

## Credentials handling

`tools/sync_sca_to_opensearch.py` needs a Wazuh API user and an OpenSearch
admin user to poll check-level SCA data and index it. It reads these,
in order of priority:

1. `WAZUH_USER` / `WAZUH_PASS` / `OS_USER` / `OS_PASS` environment variables
2. Automatically, from `wazuh-install-files.tar` (the file Wazuh's own
   all-in-one installer generates), if found under `/root`, `/home/*`,
   `/tmp`, or `/var/tmp`

Neither this script nor any other file in this repository sends those
credentials anywhere except the Wazuh API and your own OpenSearch instance
— there is no telemetry and no third-party service involved.

Because `wazuh-install-files.tar` has `700` permissions and typically
contains every generated password for the stack, the sync tool (and the
cron job `install_sync.sh` creates) runs as `root`. Review
`tools/sync_sca_to_opensearch.py` yourself before running it with
credentials you care about, as you should with any script that handles
secrets — this is a community project, not an audited one.

When reporting a bug, always redact credentials, API responses, and
`wazuh-install-files.tar` contents before pasting them anywhere public.

## Compliance content is not a substitute for review

The SCA policies and detection rules in this repository encode an
interpretation of ENS (RD 311/2022) and ISO/IEC 27001:2022 controls (see
[`docs/controls_mapping.md`](docs/controls_mapping.md) and
[`docs/iso27001_mapping.md`](docs/iso27001_mapping.md)). A bug in a check's
regex, or an incorrect control mapping, could cause a system to be reported
as compliant when it isn't. Treat this project as an aid to auditing, not
as a certification — always validate the actual checks against your own
environment and requirements before relying on the results.

## Scope

This is a community project, not officially supported by Wazuh, Inc. — the
scope of this policy is limited to the scripts, policies, and dashboards in
this repository, not the Wazuh platform itself (report those to
[wazuh/wazuh](https://github.com/wazuh/wazuh/security)).
