"""
collector.py
Connects to a Raspberry Pi over SSH and collects raw security data.
"""
import asyncio
import asyncssh
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class RawData:
    hostname: str
    ip: str
    uname: str = ""
    ports: str = ""
    firewall_status: str = ""
    pending_updates: str = ""
    failed_logins: str = ""
    users: str = ""
    ssh_config: str = ""
    disk_usage: str = ""
    running_services: str = ""
    last_login: str = ""
    cron_jobs: str = ""
    error: Optional[str] = None


COMMANDS = {
    "uname":             "uname -a",
    "ports":             "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null",
    "firewall_status":   "ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -20",
    "pending_updates":   "apt list --upgradable 2>/dev/null | grep -v 'Listing...' | wc -l",
    "failed_logins":     "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20 || echo 'no_auth_log'",
    "users":             "cat /etc/passwd | grep -v nologin | grep -v false | cut -d: -f1,3,6",
    "ssh_config":        "grep -E '^(PermitRootLogin|PasswordAuthentication|Port|MaxAuthTries)' /etc/ssh/sshd_config 2>/dev/null",
    "disk_usage":        "df -h / | tail -1",
    "running_services":  "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -30",
    "last_login":        "last -n 10 --time-format iso 2>/dev/null | head -10",
    "cron_jobs":         "crontab -l 2>/dev/null; ls /etc/cron.d/ 2>/dev/null",
}


async def collect_from_host(
    hostname: str,
    ip: str,
    ssh_user: str = "pi",
    ssh_key_path: Optional[str] = None,
    ssh_password: Optional[str] = None,
    timeout: int = 30,
) -> RawData:
    """SSH into a Pi and run all collection commands. Returns RawData."""
    data = RawData(hostname=hostname, ip=ip)

    connect_kwargs = {
        "host": ip,
        "username": ssh_user,
        "connect_timeout": timeout,
        "known_hosts": None,  # Disable host key checking for lab use
    }
    if ssh_key_path:
        connect_kwargs["client_keys"] = [ssh_key_path]
    if ssh_password:
        connect_kwargs["password"] = ssh_password

    try:
        async with asyncssh.connect(**connect_kwargs) as conn:
            tasks = {
                key: conn.run(cmd, timeout=timeout)
                for key, cmd in COMMANDS.items()
            }
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)

            for key, result in zip(tasks.keys(), results):
                if isinstance(result, Exception):
                    setattr(data, key, f"ERROR: {result}")
                else:
                    setattr(data, key, result.stdout.strip())

    except asyncssh.DisconnectError as e:
        data.error = f"SSH disconnect: {e}"
    except asyncssh.PermissionDenied:
        data.error = "SSH permission denied — check credentials"
    except asyncio.TimeoutError:
        data.error = f"Connection timed out after {timeout}s"
    except Exception as e:
        data.error = f"Unexpected error: {e}"

    return data


async def collect_from_all(hosts: list[dict], ssh_key_path: Optional[str] = None) -> list[RawData]:
    """Collect from multiple Pis concurrently."""
    tasks = [
        collect_from_host(
            hostname=h["hostname"],
            ip=h["ip"],
            ssh_user=h.get("ssh_user", "pi"),
            ssh_key_path=ssh_key_path or h.get("ssh_key_path"),
            ssh_password=h.get("ssh_password"),
        )
        for h in hosts
    ]
    return await asyncio.gather(*tasks)
