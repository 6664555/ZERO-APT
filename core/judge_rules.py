"""core/judge_rules.py - Judge adjudication threshold rule (paper §3.4, Table: judge_logic)

The winner is decided by a mechanical comparison of the Defender evidence score against a
threshold, independent of the LLM's `winner` field, so score and verdict can never contradict
(evidence_score >= 75 -> Defender wins).
"""

JUDGE_THRESHOLD = 75


def adjudicate(blue_evidence_score) -> str:
    """Return 'blue_win' or 'red_win'. A missing/non-numeric score counts as no valid evidence -> red_win."""
    try:
        score = float(blue_evidence_score)
    except (TypeError, ValueError):
        return "red_win"
    return "blue_win" if score >= JUDGE_THRESHOLD else "red_win"
