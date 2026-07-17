-- Pi Security Scorecard Schema

CREATE TABLE IF NOT EXISTS hosts (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    ssh_user VARCHAR(50) DEFAULT 'pi',
    ssh_key_path VARCHAR(255),
    added_at TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP,
    active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT NOW(),
    score INTEGER,
    risk_level VARCHAR(20),  -- Low, Medium, High, Critical
    raw_data JSONB,
    normalized_data JSONB,
    scan_duration_ms INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    severity VARCHAR(20),    -- HIGH, MEDIUM, LOW, INFO
    category VARCHAR(50),
    title VARCHAR(255),
    detail TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS port_history (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    port INTEGER,
    protocol VARCHAR(10),
    service VARCHAR(50),
    first_seen TIMESTAMP DEFAULT NOW()
);

-- Index for fast score history queries
CREATE INDEX IF NOT EXISTS idx_scans_host_timestamp ON scans(host_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_port_history_host ON port_history(host_id);
