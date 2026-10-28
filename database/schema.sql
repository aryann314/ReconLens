-- ------------------------------------------------------------
-- OSINT Dashboard - SQLite schema
-- Two tables: one row per scan, many findings per scan.
-- ------------------------------------------------------------
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type       TEXT    NOT NULL CHECK (scan_type IN ('domain','username','email','reputation')),
    target          TEXT    NOT NULL,          -- emails are stored MASKED (a***@domain)
    mode            TEXT    NOT NULL CHECK (mode IN ('demo','live')),
    status          TEXT    NOT NULL,          -- completed | partial | failed
    exposure_score  INTEGER NOT NULL DEFAULT 0,
    exposure_level  TEXT    NOT NULL DEFAULT 'Low',
    authorization   TEXT,                      -- statement the operator accepted (audit trail)
    started_at      TEXT    NOT NULL,          -- ISO-8601 UTC
    completed_at    TEXT,
    duration_ms     INTEGER,
    modules_json    TEXT,                      -- per-source status, timing, errors
    recommendations_json TEXT,
    limitations_json     TEXT,
    scoring_json         TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module        TEXT    NOT NULL,            -- e.g. dns, rdap, crtsh, username, hibp, virustotal
    source        TEXT    NOT NULL,            -- human-readable data source
    code          TEXT    NOT NULL,            -- machine code used for scoring & recommendations
    title         TEXT    NOT NULL,
    value         TEXT,
    status        TEXT    NOT NULL CHECK (status IN ('confirmed','not_found','inconclusive','error')),
    severity      TEXT    NOT NULL CHECK (severity IN ('info','low','medium','high')),
    source_url    TEXT,
    collected_at  TEXT    NOT NULL,
    details_json  TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);
