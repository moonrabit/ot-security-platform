"""
Roadmap Generation Engine.
Combines questionnaire gaps + scanner findings into a prioritized improvement plan
aligned to IEC 62443, Purdue Model, and NIST CSF.
"""
from __future__ import annotations
import json
import uuid
from pathlib import Path

from config import PRIORITY_WEIGHTS, SEVERITY_SCORES, PURDUE_EXPOSURE_SCORES

TEMPLATES_PATH = Path(__file__).parent.parent / "data" / "roadmap_templates.json"

# FR → severity weight for questionnaire-only gaps (OT-specific: availability is critical)
FR_SEVERITY_BASE = {
    1: 80,  # Auth: high
    2: 75,  # Use control
    3: 70,  # Integrity
    4: 65,  # Confidentiality
    5: 85,  # Segmentation: very high in OT
    6: 60,  # Response
    7: 90,  # Availability: CRITICAL in OT (inverted from IT)
}

# Scanner finding type → severity override
FINDING_SEVERITY_SCORES = {
    "CRITICAL": SEVERITY_SCORES["CRITICAL"],
    "HIGH":     SEVERITY_SCORES["HIGH"],
    "MEDIUM":   SEVERITY_SCORES["MEDIUM"],
    "LOW":      SEVERITY_SCORES["LOW"],
    "INFO":     SEVERITY_SCORES["INFO"],
}

# Exploit likelihood by rule_id
EXPLOIT_LIKELIHOOD = {
    "TELNET_DETECTED":            0.98,
    "OPCUA_NONE_SECURITY":        0.95,
    "MODBUS_BROADCAST_WRITE":     0.95,
    "IEC104_CONTROL_COMMAND":     0.90,
    "S7COMM_UNENCRYPTED":         0.90,
    "FTP_DETECTED":               0.90,
    "IEC104_UNENCRYPTED":         0.85,
    "DNP3_NO_AUTH":               0.85,
    "HTTP_MANAGEMENT":            0.85,
    "MODBUS_WRITE_COIL":          0.80,
    "IT_OT_DIRECT_COMMUNICATION": 0.80,
    "ENIP_FORWARD_OPEN":          0.75,
    "ENIP_UNENCRYPTED":           0.80,
    "BACNET_WRITE_PROPERTY":      0.80,
    "BACNET_UNENCRYPTED":         0.75,
    "MODBUS_UNENCRYPTED":         0.90,
    "PROFINET_UNENCRYPTED":       0.70,
    "OPCUA_SIGN_ONLY":            0.60,
    "ENIP_IDENTITY_REQUEST":      0.70,
    "BACNET_WHO_IS_BROADCAST":    0.70,
    "MODBUS_DEVICE_IDENTIFICATION": 0.60,
    "DNP3_UNSOLICITED_RESPONSE":  0.50,
}


def load_templates() -> list[dict]:
    with open(TEMPLATES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["templates"]


def generate_roadmap(
    session_id: str,
    questionnaire_gaps: list[dict],
    scanner_findings: list[dict],
    zones: list[dict],
    global_sl_target: int = 2,
) -> list[dict]:
    """
    Main entry point. Returns a list of roadmap item dicts ready for DB insertion.
    """
    templates = load_templates()

    # Step 1: Determine which templates are triggered
    triggered = _match_templates(templates, questionnaire_gaps, scanner_findings)

    # Step 2: Score each triggered template
    for item in triggered:
        item["priority_score"] = _compute_priority(
            item, questionnaire_gaps, scanner_findings, zones, global_sl_target
        )

    # Step 3: Sort by priority desc within each phase
    triggered.sort(key=lambda x: (-x["phase"], -x["priority_score"]))
    triggered.sort(key=lambda x: x["phase"])

    # Step 4: Finalize for DB
    roadmap_items = []
    for item in triggered:
        roadmap_items.append({
            "item_id":        str(uuid.uuid4()),
            "session_id":     session_id,
            "title":          item["title"],
            "description":    item["description"],
            "phase":          item["phase"],
            "priority_score": round(item["priority_score"], 1),
            "effort_days":    item["effort_days"],
            "status":         "not_started",
            "gap_ids":        item.get("matched_gap_ids", []),
            "csf_functions":  item.get("csf_functions", []),
            "nist_controls":  item.get("nist_controls", []),
            "dependencies":   _resolve_template_dependencies(item, triggered),
            "purdue_levels":  item.get("purdue_levels_affected", []),
        })

    return roadmap_items


def _match_templates(
    templates: list[dict],
    gaps: list[dict],
    findings: list[dict],
) -> list[dict]:
    """Return templates that are triggered by at least one gap or finding."""
    finding_rule_ids = {f.get("finding_type", "") for f in findings}
    finding_rule_ids |= {f.get("rule_id", "") for f in findings}
    gap_question_ids = set()
    for g in gaps:
        gap_question_ids.update(g.get("question_ids", []))
        gap_question_ids.add(g.get("gap_id", ""))

    triggered = []
    for tmpl in templates:
        matched_gap_ids = []
        triggers = tmpl.get("gap_triggers", [])
        fired = False

        for trigger in triggers:
            # Match by scanner rule ID
            if trigger in finding_rule_ids:
                fired = True
            # Match by question ID prefix (e.g. "FR1-SR1.5")
            if trigger in gap_question_ids:
                fired = True
                matched_gap_ids.append(trigger)
            # Match by gap_id pattern like "FR5-SR5.1"
            for g in gaps:
                if trigger in g.get("sr_refs", []) or trigger == g.get("gap_id", ""):
                    fired = True
                    if g["gap_id"] not in matched_gap_ids:
                        matched_gap_ids.append(g["gap_id"])

        if fired:
            item = dict(tmpl)
            item["matched_gap_ids"] = matched_gap_ids
            triggered.append(item)

    # If no triggers fired (bare minimum), add T01 (inventory) always
    if not any(t["template_id"] == "T01" for t in triggered):
        for t in templates:
            if t["template_id"] == "T01":
                item = dict(t)
                item["matched_gap_ids"] = []
                triggered.append(item)
                break

    return triggered


def _compute_priority(
    item: dict,
    gaps: list[dict],
    findings: list[dict],
    zones: list[dict],
    global_sl_target: int,
) -> float:
    """
    Priority = weighted sum of:
      severity_score (35%) + gap_magnitude (25%) + purdue_exposure (20%) +
      csf_criticality (10%) + exploit_likelihood (10%)
    All components normalized to 0–100.
    """
    W = PRIORITY_WEIGHTS

    # 1. Severity score
    finding_rule_ids = {f.get("rule_id", f.get("finding_type", "")) for f in findings}
    severity_val = item.get("priority_boost", 0)
    fr_list = item.get("addresses_fr", [])
    for fr in fr_list:
        severity_val = max(severity_val, FR_SEVERITY_BASE.get(fr, 50))
    # Boost for critical scanner findings
    for rid in finding_rule_ids:
        lk = EXPLOIT_LIKELIHOOD.get(rid, 0.5)
        if lk >= 0.9:
            severity_val = max(severity_val, 90)
        elif lk >= 0.8:
            severity_val = max(severity_val, 75)

    # 2. Gap magnitude (average across matched gaps)
    matched_gap_ids = set(item.get("matched_gap_ids", []))
    relevant_gaps = [g for g in gaps if g.get("gap_id") in matched_gap_ids]
    if relevant_gaps:
        avg_magnitude = sum(g.get("gap_magnitude", 1) for g in relevant_gaps) / len(relevant_gaps)
        gap_score = min(100, avg_magnitude / 4 * 100)
    else:
        gap_score = 50  # default

    # 3. Purdue exposure score
    purdue_levels = item.get("purdue_levels_affected", [2])
    if purdue_levels:
        exposure = max(PURDUE_EXPOSURE_SCORES.get(lvl, 50) for lvl in purdue_levels)
    else:
        exposure = 50

    # 4. CSF criticality (Protect > Detect > Respond > Identify > Recover)
    csf_scores = {"Protect": 90, "Detect": 75, "Respond": 60, "Identify": 50, "Recover": 40}
    csf_list = item.get("csf_functions", [])
    csf_score = max((csf_scores.get(f, 50) for f in csf_list), default=50)

    # 5. Exploit likelihood
    exploit_scores = [EXPLOIT_LIKELIHOOD.get(rid, 0.5) for rid in finding_rule_ids]
    exploit_score = max(exploit_scores, default=0.5) * 100

    priority = (
        W["severity"]          * severity_val +
        W["gap_magnitude"]     * gap_score +
        W["purdue_exposure"]   * exposure +
        W["csf_criticality"]   * csf_score +
        W["exploit_likelihood"] * exploit_score
    )
    return min(100.0, max(0.0, priority))


def _resolve_template_dependencies(item: dict, all_triggered: list[dict]) -> list[str]:
    """
    Map template dependency IDs (T01, T03, etc.) to actual item_ids of triggered items.
    Returns a list of item_ids (not template_ids).
    Returns empty list if dependencies not yet triggered.
    """
    dep_template_ids = item.get("dependencies", [])
    if not dep_template_ids:
        return []
    id_map = {t["template_id"]: t.get("item_id", "") for t in all_triggered if "item_id" in t}
    return [id_map[dep] for dep in dep_template_ids if dep in id_map]


def compute_csf_coverage(roadmap_items: list[dict]) -> dict:
    """
    Compute NIST CSF function coverage percentage from roadmap items.
    Returns: {"Identify": 0.6, "Protect": 0.8, ...}
    """
    from config import NIST_CSF_FUNCTIONS
    # Count unique NIST subcategories covered per function
    covered: dict[str, set] = {fn: set() for fn in NIST_CSF_FUNCTIONS.values()}
    for item in roadmap_items:
        for ctrl in item.get("nist_controls", []):
            prefix = ctrl.split(".")[0][:2]
            fn = NIST_CSF_FUNCTIONS.get(prefix)
            if fn:
                covered[fn].add(ctrl)

    # Approximate total subcategories per function (NIST CSF v1.1)
    totals = {"Identify": 6, "Protect": 35, "Detect": 18, "Respond": 16, "Recover": 8}
    return {
        fn: round(min(1.0, len(covered.get(fn, set())) / totals.get(fn, 10)), 2)
        for fn in NIST_CSF_FUNCTIONS.values()
    }


def merge_gaps_from_findings(scanner_findings: list[dict]) -> list[dict]:
    """Convert scanner findings into gap-like dicts for unified gap analysis."""
    from config import FR_TO_CSF
    # Map IEC 62443 SR ref prefix to FR number
    sr_to_fr = {}
    for fr, _ in enumerate(range(1, 8), 1):
        for i in range(1, 20):
            sr_to_fr[f"SR {fr}.{i}"] = fr

    gaps = []
    seen = set()
    for f in scanner_findings:
        iec_ref = f.get("iec62443_ref", "")
        fr = sr_to_fr.get(iec_ref, None)
        if fr is None:
            # Try to extract FR from common refs like "SR 4.1" → FR 4
            try:
                fr = int(iec_ref.split()[1].split(".")[0])
            except Exception:
                fr = 4  # default to FR4 (confidentiality) for unencrypted protocol findings

        key = f"SCAN-FR{fr}-{f.get('finding_type', 'UNKNOWN')}"
        if key in seen:
            continue
        seen.add(key)

        severity = f.get("severity", "MEDIUM")
        sev_score = FINDING_SEVERITY_SCORES.get(severity, 50)
        gaps.append({
            "gap_id": key,
            "fr_number": fr,
            "zone_id": "",
            "current_sl": 0,
            "current_pct": 0.0,
            "target_sl": 2,
            "gap_magnitude": 2.0,
            "source": "scanner",
            "question_ids": [],
            "csf_functions": [f.get("csf_function", "Protect")],
            "sr_refs": [iec_ref],
            "severity": severity,
            "severity_score": sev_score,
        })
    return gaps
