"""
normalizer.py
Parses raw command output strings into clean, typed Python dicts.
"""
import re
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class NormalizedData:
    hostname: str
    ip: str
    os_info: str = ""
    open_ports: list[int] = field(default_factory=list)
    port_details: list[dict] = field(default_factory=list)
    firewall_enabled: bool = False
    firewall_rules_count: int = 0
    pending_updates: int = 0
    failed_login_count: int = 0
    failed_login_ips: list[str] = field(default_factory=list)
    root_login_permitted: bool = False
    password_auth_enabled: bool = True
    ssh_port: int = 22
    ssh_max_auth_tries: int = 6
    disk_usage_percent: int = 0
    running_services: list[str] = field(default_factory=list)
    user_accounts: list[str] = field(default_factory=list)
    suspicious_ports: list[int] = field(default_factory=list)
    cron_jobs_present: bool = False


# Ports that are expected on a typical Pi setup
EXPECTED_PORTS = {22, 80, 443, 53, 5900}  # SSH, HTTP, HTTPS, DNS, VNC


def parse_ports(raw: str) -> tuple[list[int], list[dict]]:
    """Extract open ports from ss -tulnp output."""
    ports = []
    details = []
    for line in raw.splitlines():
        # Match lines with LISTEN state
        if "LISTEN" not in line and "UNCONN" not in line:
            continue
        # Try to extract port number from address like 0.0.0.0:22 or *:80
        match = re.search(r'[:\*](\d+)\s', line)
        if match:
            port = int(match.group(1))
            service_match = re.search(r'users:\(\("([^"]+)"', line)
            service = service_match.group(1) if service_match else "unknown"
            ports.append(port)
            details.append({"port": port, "service": service, "line": line.strip()})
    return sorted(set(ports)), details


def parse_firewall(raw: str) -> tuple[bool, int]:
    """Detect if UFW/iptables is active."""
    if "Status: active" in raw:
        rules = len([l for l in raw.splitlines() if re.match(r'^\d+', l.strip())])
        return True, rules
    if "Chain INPUT" in raw:
        # iptables fallback — if there are rules, consider active
        rules = len([l for l in raw.splitlines() if l.strip() and not l.startswith("Chain") and not l.startswith("target")])
        return rules > 2, rules
    return False, 0


def parse_ssh_config(raw: str) -> dict:
    """Parse sshd_config relevant settings."""
    config = {
        "root_login_permitted": False,
        "password_auth_enabled": True,
        "ssh_port": 22,
        "max_auth_tries": 6,
    }
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("PermitRootLogin"):
            val = line.split()[-1].lower()
            config["root_login_permitted"] = val in ("yes", "without-password", "prohibit-password")
        elif line.startswith("PasswordAuthentication"):
            config["password_auth_enabled"] = line.split()[-1].lower() == "yes"
        elif line.startswith("Port"):
            try:
                config["ssh_port"] = int(line.split()[-1])
            except ValueError:
                pass
        elif line.startswith("MaxAuthTries"):
            try:
                config["max_auth_tries"] = int(line.split()[-1])
            except ValueError:
                pass
    return config


def parse_disk_usage(raw: str) -> int:
    """Extract disk usage percentage from df output."""
    match = re.search(r'(\d+)%', raw)
    return int(match.group(1)) if match else 0


def parse_failed_logins(raw: str) -> tuple[int, list[str]]:
    """Count failed login attempts and extract source IPs."""
    if raw in ("no_auth_log", "") or raw.startswith("ERROR"):
        return 0, []
    lines = [l for l in raw.splitlines() if "Failed password" in l]
    ips = list(set(re.findall(r'from (\d+\.\d+\.\d+\.\d+)', "\n".join(lines))))
    return len(lines), ips


def parse_users(raw: str) -> list[str]:
    """Extract non-system usernames (uid >= 1000)."""
    users = []
    for line in raw.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            try:
                uid = int(parts[1])
                if uid >= 1000:
                    users.append(parts[0])
            except ValueError:
                pass
    return users


def parse_services(raw: str) -> list[str]:
    """Extract running service names."""
    services = []
    for line in raw.splitlines():
        if line.strip():
            parts = line.split()
            if parts:
                services.append(parts[0].replace(".service", ""))
    return services[:20]  # Cap at 20


def normalize(raw) -> NormalizedData:
    """Convert a RawData object into a NormalizedData object."""
    data = NormalizedData(hostname=raw.hostname, ip=raw.ip)

    data.os_info = raw.uname

    data.open_ports, data.port_details = parse_ports(raw.ports)
    data.suspicious_ports = [p for p in data.open_ports if p not in EXPECTED_PORTS and p < 10000]

    data.firewall_enabled, data.firewall_rules_count = parse_firewall(raw.firewall_status)

    try:
        data.pending_updates = int(raw.pending_updates.strip())
    except (ValueError, AttributeError):
        data.pending_updates = 0

    data.failed_login_count, data.failed_login_ips = parse_failed_logins(raw.failed_logins)

    ssh_cfg = parse_ssh_config(raw.ssh_config)
    data.root_login_permitted = ssh_cfg["root_login_permitted"]
    data.password_auth_enabled = ssh_cfg["password_auth_enabled"]
    data.ssh_port = ssh_cfg["ssh_port"]
    data.ssh_max_auth_tries = ssh_cfg["max_auth_tries"]

    data.disk_usage_percent = parse_disk_usage(raw.disk_usage)
    data.running_services = parse_services(raw.running_services)
    data.user_accounts = parse_users(raw.users)
    data.cron_jobs_present = bool(raw.cron_jobs and raw.cron_jobs.strip())

    return data
