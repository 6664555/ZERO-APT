"""tests/test_metrics_stats.py - metric computation and statistical test unit tests

Statistical implementations are calibrated against known distribution values:
- chi2(1df) 95% quantile = 3.841 -> chi2_p(1, 3.841) ~ 0.05
- t(10df) two-sided 95% quantile = 2.228 -> t_p(10, 2.228) ~ 0.05
Run: cd Zero-APT-Code && python tests/test_metrics_stats.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness.metrics import compute_experiment_metrics, aggregate
from harness.stats import chi2_yates, welch_t, friedman, pages_l, holm, cohen_d, chi2_p, t_p, wilcoxon

_PASS = 0


def _ok(name):
    global _PASS
    _PASS += 1
    print(f"  PASS {name}")


def _fail(name, msg):
    print(f"  FAIL {name}: {msg}")
    raise SystemExit(1)


def _mk_state(round_logs, goal=False, used_ids=None, backtracks=None, hct_events=None):
    return {"goal_achieved": goal,
            "round_logs": round_logs,
            "used_action_ids": used_ids or [],
            "backtracks": backtracks or {},
            "hct_events": hct_events or []}


def test_metrics_from_state():
    rl = [
        {"winner": "blue_win", "blue_evidence_score": 85,
         "blue_feedback": json.dumps({"has_intrusion": True}),
         "red_commands": [{"action": "run_command", "command": "whoami", "status": "success"},
                          {"action": "run_command", "command": "bad", "status": "failed(code=1)"}],
         "blue_rule_matches": [{"rule": "R1"}],
         "planner_reasoning": "mock plan reasoning",
         "judge_reasoning": "mock judge reasoning"},
        {"winner": "red_win", "blue_evidence_score": 40,
         "blue_feedback": json.dumps({"has_intrusion": True}),
         "red_commands": [{"action": "run_command", "command": "dir", "status": "success"},
                          {"action": "finalize", "command": "", "status": "finalized"}],
         "blue_rule_matches": [],
         "planner_reasoning": "",
         "judge_reasoning": ""},
        {"winner": "red_win", "blue_evidence_score": 20,
         "blue_feedback": json.dumps({"has_intrusion": "true"}),  # LLM string "true" must also be recognized
         "red_commands": [],
         "blue_rule_matches": [],
         "planner_reasoning": "x", "judge_reasoning": "y"},
    ]
    state = _mk_state(rl, used_ids=["T1", "T1", "T2"],
                      backtracks={"total": 4, "recovered": 2, "passive_total": 2, "passive_recovered": 1},
                      hct_events=[{"hct_count": 10}, {"hct_count": 5}])
    m = compute_experiment_metrics(state)
    assert m["Rnd"] == 3
    # TP/FP: all 3 rounds claim intrusion (including string "true"); TP=1/3, FP=2/3
    assert m["TP%"] == round(100 / 3, 2) and m["FP%"] == round(200 / 3, 2), m
    # CBF% denominator only counts run_command (3 executed commands); finalize empty entries excluded
    assert m["CBF%"] == round(100 * 1 / 3, 2), m
    assert m["HCT"] == 15
    assert m["ActD"] == 2 and m["Rpt%"] == round(100 * 1 / 3, 2)
    assert m["BSR"] == 0.5 and m["BSR_passive"] == 0.5
    assert m["CoT"] == round(4 / 6, 3), m  # 3 rounds x 2 decision steps, 4 reasoning non-empty
    assert m["ASR"] == 0 and m["CCS"] is None and m["ICC"] is None
    _ok("test_metrics_from_state")


def test_metrics_from_row():
    """row input (no round_logs) must use the row's fields, not return fake zeros."""
    row = {"goal_achieved": True, "rounds": 8, "max_loops": 8, "wall_seconds": 123.4,
           "commands_total": 10, "commands_failed": 5, "hct_total": 42,
           "used_action_ids": ["T1", "T2", "T1"],
           "backtracks": {"total": 4, "recovered": 2, "passive_total": 0, "passive_recovered": 0}}
    m = compute_experiment_metrics(row)
    assert m["Rnd"] == 8 and m["CBF%"] == 50.0 and m["HCT"] == 42, m
    assert m["ASR"] == 1 and m["Time"] == 123.4
    assert m["BSR"] == 0.5
    assert m["TP%"] is None and m["FP%"] is None, "row lacks per-round claims -> None, not fake 0"
    assert m["CoT"] is None
    _ok("test_metrics_from_row")


def test_aggregate():
    rows = [{"scheme": "zero-apt", "tier": "L1", "ASR": 1.0},
            {"scheme": "zero-apt", "tier": "L2", "ASR": 0.0},
            {"scheme": "aurora", "tier": "L1", "ASR": 0.5}]
    g = aggregate(rows, group_key="scheme", metric="ASR")
    assert g["zero-apt"] == 0.5 and g["aurora"] == 0.5, g
    _ok("test_aggregate")


def test_chi2_calibration():
    # known: chi2(1df) 95% quantile 3.841 -> p ~ 0.05
    p = chi2_p(1, 3.841)
    assert 0.04 < p < 0.06, f"chi2_p(1,3.841) must be ~0.05, got {p}"
    assert chi2_p(1, 0) == 1.0
    _ok("test_chi2_calibration")


def test_chi2_yates():
    stat, p, phi = chi2_yates([[10, 0], [0, 10]])
    assert p < 0.01 and phi >= 0.85, (stat, p, phi)  # after Yates correction phi = 0.9 (uncorrected is 1.0)
    stat, p, phi = chi2_yates([[10, 10], [10, 10]])
    assert stat == 0 and p == 1.0
    # paper H1 magnitude: 79% vs 22% (n=100) should be significant
    stat, p, phi = chi2_yates([[79, 21], [22, 78]])
    assert p < 0.001, f"79% vs 22% must be highly significant, got p={p}"
    _ok("test_chi2_yates")


def test_t_calibration():
    # known: t(10df) two-sided 95% quantile 2.228 -> p ~ 0.05
    p = t_p(10, 2.228)
    assert 0.04 < p < 0.06, f"t_p(10,2.228) must be ~0.05, got {p}"
    _ok("test_t_calibration")


def test_welch_t():
    t, df, p, d = welch_t([1, 1, 1], [1, 1, 1])
    assert t == 0 and p == 1.0
    t, df, p, d = welch_t([5, 6, 7], [1, 2, 3])
    assert t > 0 and p < 0.05, (t, df, p)
    assert d > 2.0, "large effect expected"
    _ok("test_welch_t")


def test_friedman_and_pages():
    # all-equal matrix (every condition equal) -> no difference
    stat, p = friedman([[1, 1, 1], [1, 1, 1], [1, 1, 1]])
    assert stat == 0 and p == 1.0, "all-equal matrix -> no difference"
    # identical per-row ordering (column values 1<2<3) -> significant column difference
    stat, p = friedman([[1, 2, 3], [1, 2, 3], [1, 2, 3]])
    assert stat > 0 and p < 0.05, (stat, p)
    L, p = pages_l([[3, 2, 1], [3, 2, 1], [3, 2, 1]])
    assert p < 0.05, f"monotonic ordering must be significant, got p={p}"
    _ok("test_friedman_and_pages")


def test_holm():
    res = holm([("a", 0.001), ("b", 0.01), ("c", 0.5)], alpha=0.05)
    by_name = {name: rejected for name, p, rejected in res}
    assert by_name["a"] and by_name["b"] and not by_name["c"], res
    _ok("test_holm")


def test_cohen_d():
    assert abs(cohen_d([1, 1, 1], [1, 1, 1])) == 0.0
    assert cohen_d([10, 11, 12], [1, 2, 3]) > 3.0
    _ok("test_cohen_d")


def test_wilcoxon():
    w, z, p = wilcoxon([1, 2, 3], [1, 2, 3])
    assert w == 0.0 and p == 1.0, "identical pairs -> no difference"
    w, z, p = wilcoxon([5, 6, 7, 8], [1, 2, 3, 4])
    assert w > 0 and p < 0.1, (w, z, p)
    _ok("test_wilcoxon")


if __name__ == "__main__":
    print("== ZERO-APT metrics/stats tests ==")
    for fn in (test_metrics_from_state, test_metrics_from_row, test_aggregate,
               test_chi2_calibration, test_chi2_yates, test_t_calibration,
               test_welch_t, test_friedman_and_pages, test_holm, test_cohen_d,
               test_wilcoxon):
        fn()
    print(f"== all {_PASS} tests passed ==")
