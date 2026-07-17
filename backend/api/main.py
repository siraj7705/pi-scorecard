"""
main.py — FastAPI backend for Pi Security Scorecard
"""
import json
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from database import get_pool, init_db
from collector.collector import collect_from_host, collect_from_all
from collector.normalizer import normalize
from scorer.scorer import score as compute_score


# ── Scheduler ───────────────────────────────────────────────────────────────
scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    scheduler.start()
    # Schedule automatic scans every 6 hours
    scheduler.add_job(run_all_scans_job, "interval", hours=6, id="auto_scan")
    yield
    scheduler.shutdown()


app = FastAPI(title="Pi Security Scorecard", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic Models ──────────────────────────────────────────────────────────
class HostCreate(BaseModel):
    hostname: str
    ip: str
    ssh_user: str = "pi"
    ssh_key_path: Optional[str] = None
    ssh_password: Optional[str] = None


class ScheduleUpdate(BaseModel):
    interval_hours: int


# ── Background Scan Job ──────────────────────────────────────────────────────
async def run_scan_for_host(host_id: int):
    """Full pipeline: collect → normalize → score → store."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        host = await conn.fetchrow("SELECT * FROM hosts WHERE id=$1 AND active=TRUE", host_id)
        if not host:
            return

        # Get previous ports for delta detection
        prev_scan = await conn.fetchrow(
            "SELECT normalized_data FROM scans WHERE host_id=$1 ORDER BY timestamp DESC LIMIT 1",
            host_id
        )
        previous_ports = None
        if prev_scan and prev_scan["normalized_data"]:
            prev_data = prev_scan["normalized_data"]
            if isinstance(prev_data, str):
                prev_data = json.loads(prev_data)
            previous_ports = prev_data.get("open_ports", [])

    start = datetime.now()

    # 1. Collect
    raw = await collect_from_host(
        hostname=host["hostname"],
        ip=host["ip"],
        ssh_user=host["ssh_user"],
        ssh_key_path=host["ssh_key_path"],
    )

    if raw.error:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO scans (host_id, score, risk_level, raw_data) VALUES ($1, 0, 'Unknown', $2)",
                host_id, json.dumps({"error": raw.error})
            )
        return

    # 2. Normalize
    normalized = normalize(raw)

    # 3. Score
    result = compute_score(normalized, previous_ports=previous_ports)

    duration_ms = int((datetime.now() - start).total_seconds() * 1000)

    # 4. Store
    async with pool.acquire() as conn:
        scan_id = await conn.fetchval(
            """INSERT INTO scans (host_id, score, risk_level, raw_data, normalized_data, scan_duration_ms)
               VALUES ($1, $2, $3, $4, $5, $6) RETURNING id""",
            host_id,
            result.score,
            result.risk_level,
            json.dumps(vars(raw) if hasattr(raw, "__dict__") else {}),
            json.dumps(normalized.__dict__),
            duration_ms,
        )

        # Store findings
        for f in result.findings:
            await conn.execute(
                """INSERT INTO findings (scan_id, severity, category, title, detail)
                   VALUES ($1, $2, $3, $4, $5)""",
                scan_id, f.severity, f.category, f.title, f.detail
            )

        # Store port history — new ports only
        for pd in normalized.port_details:
            existing = await conn.fetchrow(
                "SELECT id FROM port_history WHERE host_id=$1 AND port=$2",
                host_id, pd["port"]
            )
            if not existing:
                await conn.execute(
                    "INSERT INTO port_history (host_id, scan_id, port, service) VALUES ($1,$2,$3,$4)",
                    host_id, scan_id, pd["port"], pd.get("service", "unknown")
                )

        # Update last_seen
        await conn.execute("UPDATE hosts SET last_seen=NOW() WHERE id=$1", host_id)


async def run_all_scans_job():
    pool = await get_pool()
    async with pool.acquire() as conn:
        hosts = await conn.fetch("SELECT id FROM hosts WHERE active=TRUE")
    await asyncio.gather(*[run_scan_for_host(h["id"]) for h in hosts])


# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/api/hosts")
async def list_hosts():
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT h.id, h.hostname, h.ip, h.last_seen,
                   s.score, s.risk_level, s.timestamp as last_scan
            FROM hosts h
            LEFT JOIN LATERAL (
                SELECT score, risk_level, timestamp
                FROM scans WHERE host_id = h.id
                ORDER BY timestamp DESC LIMIT 1
            ) s ON TRUE
            WHERE h.active = TRUE
            ORDER BY h.hostname
        """)
    return [dict(r) for r in rows]


@app.post("/api/hosts")
async def add_host(host: HostCreate):
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO hosts (hostname, ip, ssh_user, ssh_key_path)
               VALUES ($1,$2,$3,$4) RETURNING id""",
            host.hostname, host.ip, host.ssh_user, host.ssh_key_path
        )
    return {"id": row["id"], "message": "Host added"}


@app.delete("/api/hosts/{host_id}")
async def remove_host(host_id: int):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("UPDATE hosts SET active=FALSE WHERE id=$1", host_id)
    return {"message": "Host removed"}


@app.post("/api/hosts/{host_id}/scan")
async def trigger_scan(host_id: int, background_tasks: BackgroundTasks):
    pool = await get_pool()
    async with pool.acquire() as conn:
        host = await conn.fetchrow("SELECT id FROM hosts WHERE id=$1 AND active=TRUE", host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    background_tasks.add_task(run_scan_for_host, host_id)
    return {"message": "Scan started"}


@app.post("/api/scan-all")
async def scan_all(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_all_scans_job)
    return {"message": "Scan started for all hosts"}


@app.get("/api/hosts/{host_id}")
async def get_host_detail(host_id: int):
    pool = await get_pool()
    async with pool.acquire() as conn:
        host = await conn.fetchrow("SELECT * FROM hosts WHERE id=$1 AND active=TRUE", host_id)
        if not host:
            raise HTTPException(404, "Host not found")

        latest_scan = await conn.fetchrow(
            "SELECT * FROM scans WHERE host_id=$1 ORDER BY timestamp DESC LIMIT 1",
            host_id
        )
        findings = []
        if latest_scan:
            findings = await conn.fetch(
                "SELECT * FROM findings WHERE scan_id=$1 ORDER BY severity", latest_scan["id"]
            )

        # Score history (last 30 scans)
        history = await conn.fetch(
            "SELECT timestamp, score, risk_level FROM scans WHERE host_id=$1 ORDER BY timestamp DESC LIMIT 30",
            host_id
        )

        ports = await conn.fetch(
            "SELECT port, service, first_seen FROM port_history WHERE host_id=$1 ORDER BY port",
            host_id
        )

    normalized = {}
    if latest_scan and latest_scan["normalized_data"]:
        nd = latest_scan["normalized_data"]
        normalized = json.loads(nd) if isinstance(nd, str) else nd

    return {
        "host": dict(host),
        "latest_scan": dict(latest_scan) if latest_scan else None,
        "normalized": normalized,
        "findings": [dict(f) for f in findings],
        "score_history": [dict(h) for h in reversed(history)],
        "port_history": [dict(p) for p in ports],
    }


@app.get("/api/hosts/{host_id}/scans")
async def get_scan_history(host_id: int, limit: int = 20):
    pool = await get_pool()
    async with pool.acquire() as conn:
        scans = await conn.fetch(
            """SELECT id, timestamp, score, risk_level, scan_duration_ms
               FROM scans WHERE host_id=$1 ORDER BY timestamp DESC LIMIT $2""",
            host_id, limit
        )
    return [dict(s) for s in scans]


@app.put("/api/schedule")
async def update_schedule(update: ScheduleUpdate):
    hours = max(1, min(update.interval_hours, 168))  # 1h to 1 week
    scheduler.reschedule_job("auto_scan", trigger="interval", hours=hours)
    return {"message": f"Scan interval updated to every {hours} hour(s)"}


@app.get("/api/stats")
async def global_stats():
    pool = await get_pool()
    async with pool.acquire() as conn:
        total_hosts = await conn.fetchval("SELECT COUNT(*) FROM hosts WHERE active=TRUE")
        total_scans = await conn.fetchval("SELECT COUNT(*) FROM scans")
        avg_score = await conn.fetchval(
            """SELECT AVG(score) FROM scans s
               WHERE s.timestamp = (SELECT MAX(s2.timestamp) FROM scans s2 WHERE s2.host_id=s.host_id)"""
        )
        critical_count = await conn.fetchval(
            """SELECT COUNT(*) FROM hosts h
               JOIN LATERAL (SELECT risk_level FROM scans WHERE host_id=h.id ORDER BY timestamp DESC LIMIT 1) s ON TRUE
               WHERE h.active=TRUE AND s.risk_level='Critical'"""
        )
    return {
        "total_hosts": total_hosts,
        "total_scans": total_scans,
        "average_score": round(float(avg_score), 1) if avg_score else 0,
        "critical_hosts": critical_count,
    }
