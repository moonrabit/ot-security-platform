"""
SQLite database manager for the OT Security Assessment Platform.
"""
import sqlite3
import os
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "ot_assessment.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Initialize the database, creating tables if they don't exist."""
    with open(SCHEMA_PATH, "r") as f:
        schema = f.read()
    conn = get_connection()
    conn.executescript(schema)
    conn.commit()
    conn.close()


# ─── Sessions ─────────────────────────────────────────────────────────────────

def create_session(session_id: str, org_name: str, site_name: str = "") -> None:
    from datetime import datetime
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO sessions(session_id, org_name, site_name, created_at) VALUES (?,?,?,?)",
        (session_id, org_name, site_name, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def get_recent_sessions(limit: int = 10) -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT session_id, org_name, site_name, created_at, status FROM sessions ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [tuple(r) for r in rows]


def get_session(session_id: str) -> dict | None:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM sessions WHERE session_id=?", (session_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# ─── Zones ────────────────────────────────────────────────────────────────────

def upsert_zone(zone: dict) -> None:
    import json
    conn = get_connection()
    conn.execute(
        """INSERT OR REPLACE INTO zones
           (zone_id, session_id, name, purdue_level, sl_target, sl_achieved, asset_types)
           VALUES (:zone_id, :session_id, :name, :purdue_level, :sl_target, :sl_achieved, :asset_types)""",
        {**zone, "asset_types": json.dumps(zone.get("asset_types", []))},
    )
    conn.commit()
    conn.close()


def get_zones(session_id: str) -> list[dict]:
    import json
    conn = get_connection()
    rows = conn.execute("SELECT * FROM zones WHERE session_id=?", (session_id,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["asset_types"] = json.loads(d.get("asset_types") or "[]")
        result.append(d)
    return result


def delete_zone(zone_id: str) -> None:
    conn = get_connection()
    conn.execute("DELETE FROM zones WHERE zone_id=?", (zone_id,))
    conn.commit()
    conn.close()


def update_zone_sl(zone_id: str, sl_achieved: float) -> None:
    conn = get_connection()
    conn.execute("UPDATE zones SET sl_achieved=? WHERE zone_id=?", (sl_achieved, zone_id))
    conn.commit()
    conn.close()


# ─── Conduits ─────────────────────────────────────────────────────────────────

def upsert_conduit(conduit: dict) -> None:
    import json
    conn = get_connection()
    conn.execute(
        """INSERT OR REPLACE INTO conduits
           (conduit_id, session_id, source_zone, dest_zone, protocols, has_firewall, has_dmz)
           VALUES (:conduit_id, :session_id, :source_zone, :dest_zone, :protocols, :has_firewall, :has_dmz)""",
        {**conduit, "protocols": json.dumps(conduit.get("protocols", []))},
    )
    conn.commit()
    conn.close()


def get_conduits(session_id: str) -> list[dict]:
    import json
    conn = get_connection()
    rows = conn.execute("SELECT * FROM conduits WHERE session_id=?", (session_id,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["protocols"] = json.loads(d.get("protocols") or "[]")
        result.append(d)
    return result


def delete_conduit(conduit_id: str) -> None:
    conn = get_connection()
    conn.execute("DELETE FROM conduits WHERE conduit_id=?", (conduit_id,))
    conn.commit()
    conn.close()


# ─── Questionnaire Responses ──────────────────────────────────────────────────

def upsert_response(response: dict) -> None:
    from datetime import datetime
    conn = get_connection()
    conn.execute(
        """INSERT OR REPLACE INTO responses
           (response_id, session_id, question_id, fr_number, sl_target, answer, evidence_note, zone_id, answered_at)
           VALUES (:response_id, :session_id, :question_id, :fr_number, :sl_target, :answer, :evidence_note, :zone_id, :answered_at)""",
        {**response, "answered_at": datetime.utcnow().isoformat()},
    )
    conn.commit()
    conn.close()


def get_responses(session_id: str) -> list[dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM responses WHERE session_id=?", (session_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_response(session_id: str, question_id: str, zone_id: str = "") -> dict | None:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM responses WHERE session_id=? AND question_id=? AND zone_id=?",
        (session_id, question_id, zone_id),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# ─── Scanner ──────────────────────────────────────────────────────────────────

def create_scan_session(scan: dict) -> None:
    import json
    conn = get_connection()
    conn.execute(
        """INSERT OR REPLACE INTO scan_sessions
           (scan_id, session_id, source_type, source_name, total_packets, ot_packets, protocol_stats, scanned_at)
           VALUES (:scan_id, :session_id, :source_type, :source_name, :total_packets, :ot_packets, :protocol_stats, :scanned_at)""",
        {**scan, "protocol_stats": json.dumps(scan.get("protocol_stats", {}))},
    )
    conn.commit()
    conn.close()


def get_scan_sessions(session_id: str) -> list[dict]:
    import json
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scan_sessions WHERE session_id=? ORDER BY scanned_at DESC", (session_id,)
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["protocol_stats"] = json.loads(d.get("protocol_stats") or "{}")
        result.append(d)
    return result


def insert_finding(finding: dict) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT OR IGNORE INTO findings
           (finding_id, scan_id, protocol, severity, finding_type, src_ip, dst_ip, dst_port,
            description, iec62443_ref, csf_function, recommendation)
           VALUES (:finding_id, :scan_id, :protocol, :severity, :finding_type, :src_ip, :dst_ip,
                   :dst_port, :description, :iec62443_ref, :csf_function, :recommendation)""",
        finding,
    )
    conn.commit()
    conn.close()


def insert_device(device: dict) -> None:
    import json
    conn = get_connection()
    conn.execute(
        """INSERT OR IGNORE INTO devices
           (device_id, scan_id, ip_address, mac_address, protocols, purdue_level, packet_count)
           VALUES (:device_id, :scan_id, :ip_address, :mac_address, :protocols, :purdue_level, :packet_count)""",
        {**device, "protocols": json.dumps(device.get("protocols", []))},
    )
    conn.commit()
    conn.close()


def get_findings(scan_id: str) -> list[dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_devices(scan_id: str) -> list[dict]:
    import json
    conn = get_connection()
    rows = conn.execute("SELECT * FROM devices WHERE scan_id=?", (scan_id,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["protocols"] = json.loads(d.get("protocols") or "[]")
        result.append(d)
    return result


# ─── Roadmap ──────────────────────────────────────────────────────────────────

def upsert_roadmap_item(item: dict) -> None:
    import json
    conn = get_connection()
    conn.execute(
        """INSERT OR REPLACE INTO roadmap_items
           (item_id, session_id, title, description, phase, priority_score, effort_days,
            status, gap_ids, csf_functions, nist_controls, dependencies, purdue_levels)
           VALUES (:item_id, :session_id, :title, :description, :phase, :priority_score,
                   :effort_days, :status, :gap_ids, :csf_functions, :nist_controls,
                   :dependencies, :purdue_levels)""",
        {
            **item,
            "gap_ids":       json.dumps(item.get("gap_ids", [])),
            "csf_functions": json.dumps(item.get("csf_functions", [])),
            "nist_controls": json.dumps(item.get("nist_controls", [])),
            "dependencies":  json.dumps(item.get("dependencies", [])),
            "purdue_levels": json.dumps(item.get("purdue_levels", [])),
        },
    )
    conn.commit()
    conn.close()


def get_roadmap_items(session_id: str) -> list[dict]:
    import json
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM roadmap_items WHERE session_id=? ORDER BY phase, priority_score DESC",
        (session_id,),
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        for f in ("gap_ids", "csf_functions", "nist_controls", "dependencies", "purdue_levels"):
            d[f] = json.loads(d.get(f) or "[]")
        result.append(d)
    return result


def update_roadmap_status(item_id: str, status: str) -> None:
    conn = get_connection()
    conn.execute("UPDATE roadmap_items SET status=? WHERE item_id=?", (status, item_id))
    conn.commit()
    conn.close()


def delete_roadmap_items(session_id: str) -> None:
    conn = get_connection()
    conn.execute("DELETE FROM roadmap_items WHERE session_id=?", (session_id,))
    conn.commit()
    conn.close()
