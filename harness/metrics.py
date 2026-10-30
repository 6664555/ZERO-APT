"""harness/metrics.py - 13-metric computation (paper Appendix Table: metrics_full)

Input: one experiment's state (returned by run_experiment) or a harness result row;
Output: a metric dict. Pure functions, testable with synthetic data and reusable when
aggregating the 1,400 experiments.

Definition notes (aligned with the paper appendix):
- CCS / ICC need human-expert review; code cannot produce them -> returns None (filled by an external review flow)
- Time: wall-clock seconds (PentestGPT human-interaction-delay handling is external)
- CBF%: non-zero-exit-code commands / total commands (paper: failure stems from unmet causal preconditions)
- TP%/FP%: per paper §4 "silent rounds drop out" — denominator is rounds where the Defender claimed intrusion (has_intrusion=true); TP = claimed AND Judge ruled blue_win; FP = claimed but Judge ruled red_win
- BSR = recovered backtracks / total backtracks (active: Dispatcher-triggered; passive: reroute after prior-round detection); recovered = same-round successful replan (active) or goal achieved this round (passive)
- Rpt% = steps reusing an action_id / total steps; ActD = distinct action_id count
- HCT = total mechanically hard-constraint-excluded candidates; CoT coverage = share of Planner/Judge decision steps with complete reasoning
"""

import json
import os


def _parse_blue(blue_feedback: str) -> dict:
    try:
        d = json.loads(blue_feedback) if blue_feedback else {}
    except json.JSONDecodeError:
        return {}
    # tolerate the LLM returning the string "true"/"false" (schema-less reality)
    v = d.get("has_intrusion")
    if isinstance(v, str) and v.lower() in ("true", "false"):
        d["has_intrusion"] = v.lower() == "true"
    return d


def _executed_commands(commands):
    """Only count actually-executed commands (finalize/skip empty-command entries excluded)."""
    return [c for c in commands if c.get("action") == "run_command" and c.get("command")]


def compute_experiment_metrics(state_or_row, cot_dir=None) -> dict:
    """Compute metrics from a state (with round_logs, returned by run_experiment) or a result row
    (harness-persisted line).

    state input -> full metrics; row input (round_logs not persisted with the row) -> uses the
    row's pre-extracted raw data; FP%/CoT etc. that need per-round detail return None (see notes).
    """
    src = state_or_row or {}
    has_logs = "round_logs" in src
    round_logs = src.get("round_logs", []) if has_logs else []
    n_rounds = len(round_logs) if has_logs else src.get("rounds", 0)

    # CBF% denominator only counts actually-executed commands (finalize/skip empty entries excluded)
    commands = ([c for rl in round_logs for c in (rl.get("red_commands") or [])]
                if has_logs else [])
    executed = _executed_commands(commands) if has_logs else []
    total_cmds = len(executed) if has_logs else src.get("commands_total", 0)
    failed_cmds = ([c for c in executed if c.get("status", "").startswith("failed")]
                   if has_logs else src.get("commands_failed", 0))

    # TP/FP (paper §4: silent rounds drop out of both rates):
    # denominator = rounds where the Defender claimed intrusion (has_intrusion=true); TP = claimed
    # AND Judge blue_win; FP = claimed but Judge red_win. row input lacks per-round claims -> None.
    claim_rounds = [rl for rl in round_logs
                    if _parse_blue(rl.get("blue_feedback", "")).get("has_intrusion") is True]
    tp_rounds = [rl for rl in claim_rounds if rl.get("winner") == "blue_win"]
    fp_rounds = [rl for rl in claim_rounds if rl.get("winner") == "red_win"]

    used_ids = src.get("used_action_ids", [])
    bt = src.get("backtracks", {})

    hct_total = sum(e.get("hct_count", 0) for e in src.get("hct_events", [])) if has_logs else src.get("hct_total", 0)

    # CoT coverage (paper: share of Planner/Judge decision steps with complete reasoning);
    # counted from non-empty planner_reasoning/judge_reasoning in round_logs, falling back to file count.
    cot_coverage = None
    if has_logs and n_rounds:
        n_reasoned = sum(1 for rl in round_logs if rl.get("planner_reasoning"))
        n_reasoned += sum(1 for rl in round_logs if rl.get("judge_reasoning"))
        cot_coverage = round(n_reasoned / (2 * n_rounds), 3)
    elif cot_dir:
        cot_files = [f for f in os.listdir(cot_dir) if f.startswith("round_")] if os.path.isdir(cot_dir) else []
        cot_coverage = round(len(cot_files) / n_rounds, 3) if n_rounds else None

    def _rate(num, den):
        return round(100 * num / den, 2) if den else 0.0

    return {
        # core four metrics
        "ASR": 1 if src.get("goal_achieved") else 0,
        "CBF%": _rate(len(failed_cmds) if has_logs else failed_cmds, total_cmds),
        "BSR": round(bt.get("recovered", 0) / bt.get("total", 0), 3) if bt.get("total") else None,
        "BSR_passive": round(bt.get("passive_recovered", 0) / bt.get("passive_total", 0), 3) if bt.get("passive_total") else None,
        # remaining metrics
        "Time": src.get("wall_seconds"),
        "CCS": None,  # needs human-expert review
        "Rpt%": round(100 * (len(used_ids) - len(set(used_ids))) / len(used_ids), 2) if used_ids else 0.0,
        "TP%": _rate(len(tp_rounds), len(claim_rounds)) if has_logs else None,
        "FP%": _rate(len(fp_rounds), len(claim_rounds)) if has_logs else None,
        "Rnd": n_rounds,
        "ActD": len(set(used_ids)),
        "HCT": hct_total,
        "CoT": cot_coverage,
        "ICC": None,  # needs inter-rater consistency data
    }


def aggregate(results: list, group_key: str = "scheme", metric: str = "ASR") -> dict:
    """Aggregate a metric's mean by group key (e.g. per-scheme ASR mean at L1/L2/L3)."""
    groups = {}
    for r in results:
        key = r.get(group_key, "?")
        groups.setdefault(key, []).append(r.get(metric))
    return {k: round(sum(v) / len(v), 3) for k, v in groups.items() if v}
