-- OT Security Assessment Platform - SQLite Schema

CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT PRIMARY KEY,
    org_name    TEXT NOT NULL,
    site_name   TEXT DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT,
    status      TEXT DEFAULT 'in_progress'
);

CREATE TABLE IF NOT EXISTS zones (
    zone_id      TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES sessions(session_id),
    name         TEXT NOT NULL,
    purdue_level INTEGER NOT NULL DEFAULT 2,
    sl_target    INTEGER NOT NULL DEFAULT 2,
    sl_achieved  REAL DEFAULT 0.0,
    asset_types  TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS conduits (
    conduit_id   TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES sessions(session_id),
    source_zone  TEXT,
    dest_zone    TEXT,
    protocols    TEXT DEFAULT '[]',
    has_firewall INTEGER DEFAULT 0,
    has_dmz      INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS responses (
    response_id   TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES sessions(session_id),
    question_id   TEXT NOT NULL,
    fr_number     INTEGER,
    sl_target     INTEGER DEFAULT 2,
    answer        TEXT DEFAULT 'no',
    evidence_note TEXT DEFAULT '',
    zone_id       TEXT DEFAULT '',
    answered_at   TEXT
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    scan_id        TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(session_id),
    source_type    TEXT DEFAULT 'pcap',
    source_name    TEXT DEFAULT '',
    total_packets  INTEGER DEFAULT 0,
    ot_packets     INTEGER DEFAULT 0,
    protocol_stats TEXT DEFAULT '{}',
    scanned_at     TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    device_id     TEXT PRIMARY KEY,
    scan_id       TEXT NOT NULL REFERENCES scan_sessions(scan_id),
    ip_address    TEXT,
    mac_address   TEXT DEFAULT '',
    protocols     TEXT DEFAULT '[]',
    purdue_level  INTEGER DEFAULT 2,
    packet_count  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id     TEXT PRIMARY KEY,
    scan_id        TEXT NOT NULL REFERENCES scan_sessions(scan_id),
    protocol       TEXT,
    severity       TEXT,
    finding_type   TEXT,
    src_ip         TEXT DEFAULT '',
    dst_ip         TEXT DEFAULT '',
    dst_port       INTEGER DEFAULT 0,
    description    TEXT DEFAULT '',
    iec62443_ref   TEXT DEFAULT '',
    csf_function   TEXT DEFAULT '',
    recommendation TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS roadmap_items (
    item_id        TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(session_id),
    title          TEXT NOT NULL,
    description    TEXT DEFAULT '',
    phase          INTEGER DEFAULT 1,
    priority_score REAL DEFAULT 50.0,
    effort_days    INTEGER DEFAULT 10,
    status         TEXT DEFAULT 'not_started',
    gap_ids        TEXT DEFAULT '[]',
    csf_functions  TEXT DEFAULT '[]',
    nist_controls  TEXT DEFAULT '[]',
    dependencies   TEXT DEFAULT '[]',
    purdue_levels  TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_zones_session    ON zones(session_id);
CREATE INDEX IF NOT EXISTS idx_responses_session ON responses(session_id);
CREATE INDEX IF NOT EXISTS idx_responses_question ON responses(session_id, question_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan    ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_roadmap_session  ON roadmap_items(session_id);
