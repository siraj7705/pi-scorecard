# Pi Security Scorecard — Setup Guide

## Project Structure

```
pi-scorecard/
├── backend/
│   ├── api/main.py          ← FastAPI app (all routes)
│   ├── collector/
│   │   ├── collector.py     ← SSH into Pis, run commands
│   │   └── normalizer.py    ← Parse raw output to structured JSON
│   ├── scorer/
│   │   └── scorer.py        ← Scoring engine + findings generator
│   ├── database.py          ← PostgreSQL connection pool
│   └── requirements.txt
├── frontend/
│   └── src/App.jsx          ← React dashboard (single file)
└── database/
    └── schema.sql           ← DB tables
```

---

## Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 14+
- Raspberry Pi(s) accessible via SSH with key-based auth

---

## 1. PostgreSQL Setup

```bash
# Create database
psql -U postgres -c "CREATE DATABASE pi_scorecard;"

# Tables are auto-created on first run via schema.sql
```

---

## 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variable (or create .env file)
export DATABASE_URL="postgresql://postgres:YOUR_PASSWORD@localhost:5432/pi_scorecard"

# Run the API server
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be live at http://localhost:8000
Docs at http://localhost:8000/docs

---

## 3. Frontend Setup

```bash
cd frontend

# Create React app (Vite)
npm create vite@latest . -- --template react
# Choose: React, JavaScript

# Install dependencies
npm install
npm install recharts

# Replace src/App.jsx with the provided App.jsx

# Start dev server
npm run dev
```

Dashboard at http://localhost:5173

---

## 4. Set Up SSH Keys for Pi Access

```bash
# Generate a key (if you don't have one)
ssh-keygen -t ed25519 -C "pi-scorecard" -f ~/.ssh/pi_scorecard_key

# Copy to each Pi
ssh-copy-id -i ~/.ssh/pi_scorecard_key.pub pi@192.168.1.10

# Test it
ssh -i ~/.ssh/pi_scorecard_key pi@192.168.1.10
```

---

## 5. Add Your First Pi

Via the dashboard UI: click **Add Pi**, fill in hostname, IP, and SSH key path.

Or via API directly:
```bash
curl -X POST http://localhost:8000/api/hosts \
  -H "Content-Type: application/json" \
  -d '{"hostname":"pi1","ip":"192.168.1.10","ssh_user":"pi","ssh_key_path":"/home/you/.ssh/pi_scorecard_key"}'
```

Then click **Scan Now** in the dashboard.

---

## Scoring Weights

| Control             | Points |
|---------------------|--------|
| SSH Hardening       | 20     |
| Pending Updates     | 20     |
| Firewall            | 15     |
| Open Ports          | 15     |
| Failed Logins       | 10     |
| Disk Usage          | 10     |
| (SSH Password Auth) | (in SSH)|
| **Total**           | **100**|

## Risk Levels

| Score   | Risk     |
|---------|----------|
| 85–100  | Low      |
| 65–84   | Medium   |
| 40–64   | High     |
| 0–39    | Critical |

---

## Key Features

- **Delta detection** — if a new port opens since the last scan, a HIGH finding is generated automatically
- **Auto-scheduling** — scans run every 6 hours by default, configurable in the UI
- **Full history** — every scan stored; score trend chart per host
- **Findings engine** — actionable findings with severity, not just a number
- **Port history** — tracks when each port was first seen

---

## Troubleshooting

**SSH permission denied** — make sure the key is copied to the Pi and the path is correct.

**Can't connect** — verify the Pi is on the same network and the IP is right. Try `ping <ip>` first.

**ufw not found** — some Pi images don't have UFW pre-installed. The collector falls back to iptables.

**apt list --upgradable hangs** — add `--no-all-versions` flag in collector.py line for pending_updates.
