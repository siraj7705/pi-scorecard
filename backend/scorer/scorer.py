"""
scorer.py
Converts NormalizedData into a numeric score, risk level, and findings list.

Weights:
  Firewall          15
  SSH Hardening     20
  Pending Updates   20
  Open Ports        15
  Failed Logins     10
  Disk Usage        10
  Password Auth     10
  ─────────────────────
  Total            100
"""
from dataclasses import dataclass, field
from .normalizer import NormalizedData


@dataclass
class Finding:
    severity: str      # HIGH | MEDIUM | LOW | INFO
    category: str
    title: str
    detail: str


@dataclass
class ScanResult:
    hostname: str
    ip: str
    score: int
    risk_level: str
    findings: list[Finding] = field(default_factory=list)
    score_breakdown: dict = field(default_factory=dict)


def risk_label(score: int) -> str:
    if score >= 85:
        return "Low"
    if score >= 65:
        return "Medium"
    if score >= 40:
        return "High"
    return "Critical"


def score(normalized: NormalizedData, previous_ports: list[int] = None) -> ScanResult:
    """
    Score a Pi based on its normalized data.
    Optionally pass previous scan's open ports to detect new ones.
    """
    total = 100
    findings: list[Finding] = []
    breakdown = {}

    # ── Firewall (15 pts) ────────────────────────────────────────────────────
    firewall_score = 15
    if not normalized.firewall_enabled:
        firewall_score = 0
        findings.append(Finding(
            severity="HIGH",
            category="Firewall",
            title="Firewall is disabled",
            detail="UFW/iptables is not active. All ports are reachable with no filtering.",
        ))
    elif normalized.firewall_rules_count < 3:
        firewall_score = 8
        findings.append(Finding(
            severity="MEDIUM",
            category="Firewall",
            title="Firewall enabled but minimal rules",
            detail=f"Only {normalized.firewall_rules_count} rule(s) detected. Review your firewall policy.",
        ))
    breakdown["firewall"] = firewall_score
    total -= (15 - firewall_score)

    # ── SSH Hardening (20 pts) ───────────────────────────────────────────────
    ssh_score = 20
    if normalized.root_login_permitted:
        ssh_score -= 10
        findings.append(Finding(
            severity="HIGH",
            category="SSH",
            title="Root login permitted via SSH",
            detail="PermitRootLogin is not set to 'no'. Direct root SSH access is a significant risk.",
        ))
    if normalized.password_auth_enabled:
        ssh_score -= 5
        findings.append(Finding(
            severity="MEDIUM",
            category="SSH",
            title="SSH password authentication enabled",
            detail="PasswordAuthentication is 'yes'. Prefer key-based auth only (set to 'no').",
        ))
    if normalized.ssh_port == 22:
        findings.append(Finding(
            severity="LOW",
            category="SSH",
            title="SSH running on default port 22",
            detail="Using a non-standard port reduces automated scan noise, though is not a security fix.",
        ))
    if normalized.ssh_max_auth_tries > 4:
        ssh_score -= 3
        findings.append(Finding(
            severity="LOW",
            category="SSH",
            title=f"MaxAuthTries set to {normalized.ssh_max_auth_tries}",
            detail="Lower MaxAuthTries to 3 or fewer to limit brute-force attempts.",
        ))
    ssh_score = max(ssh_score, 0)
    breakdown["ssh"] = ssh_score
    total -= (20 - ssh_score)

    # ── Pending Updates (20 pts) ─────────────────────────────────────────────
    updates_score = 20
    u = normalized.pending_updates
    if u > 20:
        updates_score = 0
        findings.append(Finding(
            severity="HIGH",
            category="Updates",
            title=f"{u} pending system updates",
            detail="Large number of pending updates indicates the system is significantly out of date.",
        ))
    elif u > 10:
        updates_score = 10
        findings.append(Finding(
            severity="MEDIUM",
            category="Updates",
            title=f"{u} pending system updates",
            detail="Run `sudo apt upgrade` to apply pending patches.",
        ))
    elif u > 0:
        updates_score = 15
        findings.append(Finding(
            severity="LOW",
            category="Updates",
            title=f"{u} pending system update(s)",
            detail="Minor updates available. Consider scheduling regular patching.",
        ))
    breakdown["updates"] = updates_score
    total -= (20 - updates_score)

    # ── Open Ports (15 pts) ──────────────────────────────────────────────────
    ports_score = 15
    if normalized.suspicious_ports:
        ports_score -= min(len(normalized.suspicious_ports) * 5, 15)
        findings.append(Finding(
            severity="HIGH",
            category="Ports",
            title=f"Unexpected port(s) open: {normalized.suspicious_ports}",
            detail=(
                f"Ports {normalized.suspicious_ports} are open but not in the expected set. "
                "Investigate what process is listening and close if not needed."
            ),
        ))
    ports_score = max(ports_score, 0)
    breakdown["ports"] = ports_score
    total -= (15 - ports_score)

    # ── Delta Detection — new ports since last scan ──────────────────────────
    if previous_ports is not None:
        new_ports = [p for p in normalized.open_ports if p not in previous_ports]
        if new_ports:
            findings.insert(0, Finding(
                severity="HIGH",
                category="Ports",
                title=f"NEW port(s) opened since last scan: {new_ports}",
                detail=(
                    f"Port(s) {new_ports} were not present in the previous scan. "
                    "This could indicate a new service or a compromise."
                ),
            ))

    # ── Failed Logins (10 pts) ───────────────────────────────────────────────
    logins_score = 10
    f = normalized.failed_login_count
    if f > 50:
        logins_score = 0
        findings.append(Finding(
            severity="HIGH",
            category="Authentication",
            title=f"{f} failed SSH login attempts detected",
            detail=f"Source IPs: {', '.join(normalized.failed_login_ips[:5])}. Consider fail2ban or IP blocking.",
        ))
    elif f > 10:
        logins_score = 5
        findings.append(Finding(
            severity="MEDIUM",
            category="Authentication",
            title=f"{f} failed SSH login attempts",
            detail="Elevated failed login count. Review auth.log and consider rate limiting.",
        ))
    breakdown["failed_logins"] = logins_score
    total -= (10 - logins_score)

    # ── Disk Usage (10 pts) ──────────────────────────────────────────────────
    disk_score = 10
    d = normalized.disk_usage_percent
    if d >= 90:
        disk_score = 0
        findings.append(Finding(
            severity="HIGH",
            category="Disk",
            title=f"Disk usage critical: {d}%",
            detail="System is nearly full. Logs may stop, services may crash.",
        ))
    elif d >= 80:
        disk_score = 5
        findings.append(Finding(
            severity="MEDIUM",
            category="Disk",
            title=f"Disk usage high: {d}%",
            detail="Consider cleaning up old logs or expanding storage.",
        ))
    breakdown["disk"] = disk_score
    total -= (10 - disk_score)

    # ── Password Auth double-counted in SSH, skip here ──────────────────────
    # (already deducted above under SSH hardening)

    final_score = max(min(total, 100), 0)
    return ScanResult(
        hostname=normalized.hostname,
        ip=normalized.ip,
        score=final_score,
        risk_level=risk_label(final_score),
        findings=findings,
        score_breakdown=breakdown,
    )
