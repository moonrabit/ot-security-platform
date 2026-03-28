"""
IEC 62443 Questionnaire Engine.
Loads questions, computes Security Level scores, and produces gap analysis.
"""
import json
from pathlib import Path
from typing import Optional

DATA_PATH = Path(__file__).parent.parent / "data" / "iec62443_questions.json"


def load_questions() -> list[dict]:
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def get_questions_by_fr(fr_number: int) -> list[dict]:
    return [q for q in load_questions() if q["fr_number"] == fr_number]


def get_question(question_id: str) -> Optional[dict]:
    return next((q for q in load_questions() if q["question_id"] == question_id), None)


# Answer → numeric score mapping
ANSWER_SCORES = {
    "fully":     1.0,
    "partially": 0.5,
    "no":        0.0,
    "na":        None,   # excluded from denominator
}


def score_responses(responses: list[dict]) -> dict:
    """
    Compute FR-level scores from a list of response dicts.

    Returns:
        {
          "fr_scores": {1: 0.75, 2: 0.60, ...},   # 0.0–1.0 per FR
          "overall_pct": 0.68,
          "fr_achieved_sl": {1: 2, 2: 1, ...},     # Highest SL achieved per FR
          "overall_sl": 1,                          # min across all FRs
          "answered_count": 32,
          "total_applicable": 40,
        }
    """
    questions = {q["question_id"]: q for q in load_questions()}
    # Build lookup: question_id → answer
    resp_map: dict[str, str] = {}
    for r in responses:
        key = r["question_id"]
        resp_map[key] = r.get("answer", "no")

    fr_scores: dict[int, float] = {}
    fr_achieved_sl: dict[int, int] = {}

    for fr in range(1, 8):
        fr_questions = [q for q in questions.values() if q["fr_number"] == fr]
        if not fr_questions:
            fr_scores[fr] = 0.0
            fr_achieved_sl[fr] = 0
            continue

        total_weight = 0.0
        earned = 0.0
        for q in fr_questions:
            answer = resp_map.get(q["question_id"], "no")
            score = ANSWER_SCORES.get(answer)
            if score is None:
                continue  # N/A excluded
            total_weight += 1.0
            earned += score

        pct = earned / total_weight if total_weight > 0 else 0.0
        fr_scores[fr] = round(pct, 3)

        # Determine highest SL achieved for this FR
        # SL thresholds: SL1≥40%, SL2≥65%, SL3≥80%, SL4≥95%
        sl_thresholds = {1: 0.40, 2: 0.65, 3: 0.80, 4: 0.95}
        achieved = 0
        for sl, threshold in sorted(sl_thresholds.items()):
            if pct >= threshold:
                achieved = sl
        fr_achieved_sl[fr] = achieved

    answered_count = sum(
        1 for q_id in resp_map if resp_map[q_id] not in ("", None)
    )
    total_applicable = sum(
        1 for q in questions.values()
        if resp_map.get(q["question_id"], "no") != "na"
    )

    overall_pct = sum(fr_scores.values()) / 7
    overall_sl = min(fr_achieved_sl.values()) if fr_achieved_sl else 0

    return {
        "fr_scores": fr_scores,
        "overall_pct": round(overall_pct, 3),
        "fr_achieved_sl": fr_achieved_sl,
        "overall_sl": overall_sl,
        "answered_count": answered_count,
        "total_applicable": total_applicable,
    }


def compute_gaps(responses: list[dict], zones: list[dict], global_sl_target: int = 2) -> list[dict]:
    """
    Produce a list of gap dicts from questionnaire responses.

    Each gap:
        {
          "gap_id": str,
          "fr_number": int,
          "zone_id": str,
          "current_sl": float,
          "target_sl": int,
          "gap_magnitude": float,
          "source": "questionnaire",
          "question_ids": [...],
          "csf_functions": [...],
          "sr_refs": [...],
        }
    """
    questions = {q["question_id"]: q for q in load_questions()}
    gaps = []

    # Determine target SL per zone (or global)
    zone_sl_map = {z["zone_id"]: z.get("sl_target", global_sl_target) for z in zones}

    for fr in range(1, 8):
        fr_questions = [q for q in questions.values() if q["fr_number"] == fr]

        # Score globally (no zone filter)
        global_responses = [r for r in responses if r.get("zone_id", "") == ""]
        fr_global_resps = [r for r in global_responses if questions.get(r["question_id"], {}).get("fr_number") == fr]
        global_score = _score_fr(fr_questions, fr_global_resps)
        global_sl = _pct_to_sl(global_score)
        target_sl = global_sl_target

        if global_sl < target_sl:
            weak_questions = _get_weak_questions(fr_questions, fr_global_resps)
            gaps.append({
                "gap_id": f"G-FR{fr}-GLOBAL",
                "fr_number": fr,
                "zone_id": "",
                "current_sl": global_sl,
                "current_pct": global_score,
                "target_sl": target_sl,
                "gap_magnitude": target_sl - global_sl,
                "source": "questionnaire",
                "question_ids": [q["question_id"] for q in weak_questions],
                "csf_functions": list({q.get("csf_function", "") for q in weak_questions}),
                "sr_refs": list({q.get("sr_ref", "") for q in weak_questions}),
            })

        # Score per zone
        for zone in zones:
            zone_id = zone["zone_id"]
            zone_responses = [r for r in responses if r.get("zone_id", "") == zone_id]
            fr_zone_resps = [r for r in zone_responses if questions.get(r["question_id"], {}).get("fr_number") == fr]
            if not fr_zone_resps:
                continue
            zone_score = _score_fr(fr_questions, fr_zone_resps)
            zone_sl = _pct_to_sl(zone_score)
            zone_target = zone_sl_map.get(zone_id, global_sl_target)

            if zone_sl < zone_target:
                weak_questions = _get_weak_questions(fr_questions, fr_zone_resps)
                gaps.append({
                    "gap_id": f"G-FR{fr}-{zone_id[:8]}",
                    "fr_number": fr,
                    "zone_id": zone_id,
                    "current_sl": zone_sl,
                    "current_pct": zone_score,
                    "target_sl": zone_target,
                    "gap_magnitude": zone_target - zone_sl,
                    "source": "questionnaire",
                    "question_ids": [q["question_id"] for q in weak_questions],
                    "csf_functions": list({q.get("csf_function", "") for q in weak_questions}),
                    "sr_refs": list({q.get("sr_ref", "") for q in weak_questions}),
                })

    return gaps


def _score_fr(fr_questions: list[dict], responses: list[dict]) -> float:
    resp_map = {r["question_id"]: r.get("answer", "no") for r in responses}
    total = 0.0
    earned = 0.0
    for q in fr_questions:
        answer = resp_map.get(q["question_id"], "no")
        score = ANSWER_SCORES.get(answer)
        if score is None:
            continue
        total += 1.0
        earned += score
    return round(earned / total, 3) if total > 0 else 0.0


def _pct_to_sl(pct: float) -> int:
    if pct >= 0.95:
        return 4
    if pct >= 0.80:
        return 3
    if pct >= 0.65:
        return 2
    if pct >= 0.40:
        return 1
    return 0


def _get_weak_questions(fr_questions: list[dict], responses: list[dict]) -> list[dict]:
    """Return questions answered 'no' or 'partially' (largest gaps first)."""
    resp_map = {r["question_id"]: r.get("answer", "no") for r in responses}
    weak = []
    for q in fr_questions:
        answer = resp_map.get(q["question_id"], "no")
        if answer in ("no", "partially"):
            weak.append(q)
    return weak


def get_completion_stats(responses: list[dict]) -> dict:
    """Return per-FR completion percentage."""
    questions = load_questions()
    total_by_fr = {}
    answered_by_fr = {}
    for q in questions:
        fr = q["fr_number"]
        total_by_fr[fr] = total_by_fr.get(fr, 0) + 1

    resp_map = {r["question_id"]: r.get("answer", "") for r in responses}
    for q in questions:
        fr = q["fr_number"]
        if resp_map.get(q["question_id"], "") not in ("", None):
            answered_by_fr[fr] = answered_by_fr.get(fr, 0) + 1

    result = {}
    for fr in range(1, 8):
        total = total_by_fr.get(fr, 0)
        answered = answered_by_fr.get(fr, 0)
        result[fr] = {"total": total, "answered": answered, "pct": answered / total if total else 0.0}
    return result
