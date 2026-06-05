#!/usr/bin/env python3
"""
ENS Windows Registry Collector for Wazuh SCA (remote mode).

Connects to Windows hosts via WinRM (primary) or SSH (fallback) and
collects the registry values needed to evaluate ens_windows_remote.yml
from a Linux Wazuh manager/agent.

Output file format (consumed by ens_windows_remote.yml f: rules):
  ProductName=Windows 10 Pro
  MinimumPasswordLength=14
  ...

Usage:
  python3 collect_registry.py 192.168.1.10 --username Administrator --password s3cr3t
  python3 collect_registry.py 192.168.1.10 --username svc_wazuh --key-file ~/.ssh/id_rsa --transport ssh
  python3 collect_registry.py hosts.txt --username Administrator --password s3cr3t --batch

Dependencies:
  pip install pywinrm    (WinRM transport)
  pip install paramiko   (SSH transport)
"""

import argparse
import datetime
import os
import re
import sys

# ---------------------------------------------------------------------------
# Registry keys to collect — mirrors ens_windows.yml checks exactly.
# Format: (output_key, hive, registry_path, value_name)
# ---------------------------------------------------------------------------
REGISTRY_QUERIES = [
    # requirements
    ("ProductName",
     "HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName"),
    # 31010
    ("MinimumPasswordLength",
     "HKLM", r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "MinimumPasswordLength"),
    # 31011
    ("MaximumPasswordAge",
     "HKLM", r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "MaximumPasswordAge"),
    # 31030
    ("LockoutBadCount",
     "HKLM", r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "LockoutBadCount"),
    # 31031
    ("EnableFirewall.Domain",
     "HKLM", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall"),
    ("EnableFirewall.Standard",
     "HKLM", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall"),
    ("EnableFirewall.Public",
     "HKLM", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall"),
    # 31100
    ("DisableAntiSpyware",
     "HKLM", r"SOFTWARE\Microsoft\Windows Defender", "DisableAntiSpyware"),
    # 31101
    ("DisableRealtimeMonitoring",
     "HKLM", r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
    # 31120
    ("EventLog.Security.Start",
     "HKLM", r"SYSTEM\CurrentControlSet\Services\EventLog\Security", "Start"),
    # 31400 — HKCU is user-specific; WinRM runs as the authenticated user
    ("ScreenSaveTimeOut",
     "HKCU", r"Control Panel\Desktop", "ScreenSaveTimeOut"),
    # 31700
    ("AUOptions",
     "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update", "AUOptions"),
]

NOT_FOUND = "__NOT_FOUND__"
ERROR_VAL = "__ERROR__"


# ---------------------------------------------------------------------------
# PowerShell snippet used by both transports
# ---------------------------------------------------------------------------

def _ps_query(hive, key_path, value_name):
    """Return a PowerShell one-liner that prints the registry value or NOT_FOUND."""
    full_key = f"{hive}\\{key_path}"
    return (
        f"try {{ "
        f"$v = (Get-ItemProperty -Path 'Registry::{full_key}' "
        f"-Name '{value_name}' -ErrorAction Stop).'{value_name}'; "
        f"Write-Output $v "
        f"}} catch {{ Write-Output '{NOT_FOUND}' }}"
    )


# ---------------------------------------------------------------------------
# WinRM transport
# ---------------------------------------------------------------------------

def collect_via_winrm(host, username, password, port, use_ssl):
    try:
        import winrm  # noqa: PLC0415
    except ImportError:
        return None, "pywinrm not installed — run: pip install pywinrm"

    scheme = "https" if use_ssl else "http"
    session = winrm.Session(
        f"{scheme}://{host}:{port}/wsman",
        auth=(username, password),
        transport="ntlm",
        server_cert_validation="ignore" if use_ssl else "ignore",
    )

    results = {}
    for output_key, hive, key_path, value_name in REGISTRY_QUERIES:
        ps = _ps_query(hive, key_path, value_name)
        try:
            r = session.run_ps(ps)
            value = r.std_out.decode("utf-8", errors="replace").strip()
            if not value:
                value = NOT_FOUND
        except Exception as exc:  # noqa: BLE001
            value = ERROR_VAL
            print(f"[WARN] WinRM query failed for {output_key}: {exc}", file=sys.stderr)
        results[output_key] = value

    return results, None


# ---------------------------------------------------------------------------
# SSH transport
# ---------------------------------------------------------------------------

def collect_via_ssh(host, username, password, key_file, port):
    try:
        import paramiko  # noqa: PLC0415
    except ImportError:
        return None, "paramiko not installed — run: pip install paramiko"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {"hostname": host, "port": port, "username": username}
    if key_file:
        connect_kwargs["key_filename"] = key_file
    if password:
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
    except Exception as exc:  # noqa: BLE001
        return None, f"SSH connection failed: {exc}"

    results = {}
    try:
        for output_key, hive, key_path, value_name in REGISTRY_QUERIES:
            ps = _ps_query(hive, key_path, value_name)
            cmd = f'powershell -NonInteractive -Command "{ps}"'
            try:
                _, stdout, stderr = client.exec_command(cmd, timeout=15)
                value = stdout.read().decode("utf-8", errors="replace").strip()
                if not value:
                    value = NOT_FOUND
            except Exception as exc:  # noqa: BLE001
                value = ERROR_VAL
                print(f"[WARN] SSH query failed for {output_key}: {exc}", file=sys.stderr)
            results[output_key] = value
    finally:
        client.close()

    return results, None


# ---------------------------------------------------------------------------
# Snapshot writer
# ---------------------------------------------------------------------------

def write_snapshot(results, host, transport, output_path):
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# ENS Windows Registry Snapshot\n")
        f.write(f"# Host: {host}\n")
        f.write(f"# Collected: {timestamp}\n")
        f.write(f"# Transport: {transport}\n")
        f.write(f"# Collector: ENS-Wazuh-integration\n")
        f.write("\n")
        for output_key, value in results.items():
            f.write(f"{output_key}={value}\n")


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------

def sanitize_hostname(host):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", host)


def output_path_for(host, base_dir, single_host):
    if single_host:
        return os.path.join(base_dir, "ens_windows_snapshot.cfg")
    return os.path.join(base_dir, f"ens_windows_{sanitize_hostname(host)}.cfg")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_host(host, args):
    """Collect from a single host. Returns (transport_used, error_or_None)."""
    results = None
    transport_used = None

    if args.transport in ("winrm", "auto"):
        results, err = collect_via_winrm(
            host, args.username, args.password,
            args.winrm_port, args.winrm_ssl,
        )
        if results is not None:
            transport_used = "winrm"
        elif args.transport == "winrm":
            return None, f"WinRM failed: {err}"
        else:
            print(f"[INFO] WinRM unavailable ({err}), trying SSH...", file=sys.stderr)

    if results is None and args.transport in ("ssh", "auto"):
        results, err = collect_via_ssh(
            host, args.username, args.password,
            args.key_file, args.ssh_port,
        )
        if results is not None:
            transport_used = "ssh"
        else:
            return None, f"SSH failed: {err}"

    out = output_path_for(host, args.output_dir, args.transport != "auto" or not args.batch)
    write_snapshot(results, host, transport_used, out)
    return transport_used, None


def main():
    parser = argparse.ArgumentParser(
        description="Collect Windows registry values for ENS Wazuh SCA (remote mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        help="Windows host IP/hostname, or path to a hosts file (one host per line) when --batch is set",
    )
    parser.add_argument("--username", required=True, help="Windows username")
    parser.add_argument("--password", default=None, help="Windows password")
    parser.add_argument("--key-file", dest="key_file", default=None,
                        help="SSH private key file (SSH transport only)")
    parser.add_argument(
        "--transport", choices=["winrm", "ssh", "auto"], default="auto",
        help="Connection transport. 'auto' tries WinRM first, then SSH (default: auto)",
    )
    parser.add_argument("--winrm-port", dest="winrm_port", type=int, default=5985,
                        help="WinRM port (default: 5985)")
    parser.add_argument("--winrm-ssl", dest="winrm_ssl", action="store_true",
                        help="Use HTTPS for WinRM (port 5986)")
    parser.add_argument("--ssh-port", dest="ssh_port", type=int, default=22,
                        help="SSH port (default: 22)")
    parser.add_argument(
        "--output-dir", dest="output_dir", default="/var/ossec/tmp",
        help="Directory to write snapshot files (default: /var/ossec/tmp)",
    )
    parser.add_argument(
        "--batch", action="store_true",
        help="Read hosts from a file (one per line); writes one snapshot per host",
    )
    args = parser.parse_args()

    if args.winrm_ssl and args.winrm_port == 5985:
        args.winrm_port = 5986

    if args.batch:
        try:
            with open(args.target) as f:
                hosts = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except OSError as exc:
            print(f"[ERROR] Cannot read hosts file: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        hosts = [args.target]

    failed = []
    for host in hosts:
        print(f"[...] Collecting from {host}...", file=sys.stderr)
        transport, err = run_host(host, args)
        if err:
            print(f"[ERROR] {host}: {err}", file=sys.stderr)
            failed.append(host)
        else:
            out = output_path_for(host, args.output_dir, not args.batch)
            print(f"[OK]  {host} → {out} (via {transport})")

    if failed:
        print(f"\n[WARN] Failed hosts: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
