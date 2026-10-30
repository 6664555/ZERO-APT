"""tests/test_harness_dryrun.py - batch-scheduling dry-run full-loop test (mock LLM + fake adapters, zero network/zero range)

Verifies: batch scheduling (3 schemes x 1 scenario x 1 tier x 2 reps = 6 experiments) runs
end-to-end, results JSONL persisted, ablation behavior difference (mechanical filtering only in
zero-apt), Defender signature rules actually triggering on a fake log source.
Run: cd Zero-APT-Code && python tests/test_harness_dryrun.py
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# test artifacts all go to a temp dir (OUTPUT_DIR set before utils/logger.py is first imported)
_TMP = tempfile.mkdtemp(prefix="zeroapt_test_")
os.environ["OUTPUT_DIR"] = _TMP

from core.state import Target_info
from core.loop import run_experiment
from executor.scan_action import _load_actions, build_index
from harness.fake_adapters import build_dryrun_adapters, FakeLogSource
from harness.runner import run_batch
from harness.metrics import compute_experiment_metrics
from core.defender_rules import NOISE_TEMPLATES

_PASS = 0


def _ok(name):
    global _PASS
    _PASS += 1
    print(f"  PASS {name}")


def _fail(name, msg):
    print(f"  FAIL {name}: {msg}")
    raise SystemExit(1)


def _target_info():
    return Target_info(hostname="ZEROAPTtarget", ip_address="192.168.32.139",
                       os_version="windows server 2022", user_name="User1",
                       password="mock-pass", admin_name="Administrator", admin_password="")


def test_batch_dryrun():
    lib = _load_actions()
    idx = build_index(lib)
    plan = {"schemes": ["zero-apt", "actionlib_off", "multireact_off"],
            "scenarios": ["S1"], "tiers": ["L2"], "reps": 2}
    adapters = build_dryrun_adapters()
    res = run_batch(plan, _target_info(), lib, idx, api_key=None, LLM_type='mock',
                    out_dir=os.path.join(_TMP, "results_test"), **adapters)
    rows = res["rows"]
    assert len(rows) == 6, f"expect 6 experiments, got {len(rows)}"
    with open(res["out_path"], encoding="utf-8") as f:
        lines = f.readlines()
    assert len(lines) == 6, "JSONL must have one line per experiment"
    row0 = json.loads(lines[0])
    assert row0["scheme"] == "zero-apt" and row0["defender_tier"] == "L2" and row0["rep"] == 1
    assert row0["rounds"] > 0 and row0["max_loops"] == 8
    # ablation behavior difference: mechanical filtering only in zero-apt
    for r in rows:
        if r["scheme"] == "zero-apt":
            assert r["hct_total"] > 0, "zero-apt must record mechanical HCT exclusions"
        else:
            assert r["hct_total"] == 0, f"{r['scheme']} has no dispatcher filter"
    # mock environment resetter was called
    assert adapters["resetter"].calls, "resetter must be called before each experiment"
    print(f"    result rows written to {res['out_path']}")
    _ok("test_batch_dryrun")


def test_single_experiment_metrics():
    lib = _load_actions()
    idx = build_index(lib)
    adapters = build_dryrun_adapters()
    state = run_experiment(_target_info(), lib, mission="Extract local credentials",
                           max_loops=8, action_index=idx, api_key=None, LLM_type='mock',
                           defender_tier="L2", variant="full",
                           runner=adapters["runner"], log_source=adapters["log_source"])
    m = compute_experiment_metrics(state)
    assert m["Rnd"] == 8, f"mock never achieves goal -> full 8 rounds, got {m['Rnd']}"
    assert m["ASR"] == 0 and m["TP%"] == 0.0 and m["FP%"] == 0.0
    assert m["HCT"] > 0, "mechanical filter must record exclusions"
    assert m["CBF%"] == 0.0, "mock executor finalizes without commands"
    assert m["BSR"] is None or m["BSR"] == 0.0  # returns None when there are no backtrack events
    _ok("test_single_experiment_metrics")


def test_defender_rules_on_fake_logs():
    lib = _load_actions()
    idx = build_index(lib)
    adapters = build_dryrun_adapters(log_events=[FakeLogSource.ATTACK_EVENT])
    state = run_experiment(_target_info(), lib, mission="test", max_loops=1,
                           action_index=idx, api_key=None, LLM_type='mock',
                           defender_tier="L2", variant="full",
                           runner=adapters["runner"], log_source=adapters["log_source"])
    rl0 = state["round_logs"][0]
    assert rl0["blue_rule_matches"], "ATTACK_EVENT must trigger signature rule R1 under L2"
    assert rl0["blue_rule_matches"][0]["rule"] == "R1_suspicious_parent_child"
    _ok("test_defender_rules_on_fake_logs")


def test_l1_noise_reaches_monitor():
    """L1 noise must still reach the Monitor with 25 real events (blind-review C5: truncation-fix verification)."""
    events = [dict(FakeLogSource.BENIGN_EVENT) for _ in range(25)]
    lib = _load_actions()
    idx = build_index(lib)
    adapters = build_dryrun_adapters(log_events=events)
    state = run_experiment(_target_info(), lib, mission="test", max_loops=1,
                           action_index=idx, api_key=None, LLM_type='mock',
                           defender_tier="L1", variant="full",
                           runner=adapters["runner"], log_source=adapters["log_source"])
    logs = state.get("blue_input_logs", "")
    hit = any(msg.split("|")[-1].strip() in logs for _, _, msg in NOISE_TEMPLATES)
    assert hit, "L1 noise must appear in Monitor input even with 25 real events"
    _ok("test_l1_noise_reaches_monitor")


def test_fail_fast_without_key():
    """A non-mock backend missing a key must fail at startup (blind-review C6), never silently produce fake results."""
    saved = {k: os.environ.pop(k, None) for k in ("DEEPSEEK_API_KEY", "CLAUDE_API_KEY")}
    try:
        lib = _load_actions()
        idx = build_index(lib)
        adapters = build_dryrun_adapters()
        try:
            run_experiment(_target_info(), lib, mission="test", max_loops=1,
                           action_index=idx, api_key=None, LLM_type='deepseek',
                           defender_tier="L2", runner=adapters["runner"],
                           log_source=adapters["log_source"])
            raise AssertionError("expected RuntimeError for missing API key")
        except RuntimeError as e:
            assert "API key" in str(e)
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
    _ok("test_fail_fast_without_key")


def test_cleanup_test_outputs():
    import shutil
    shutil.rmtree(_TMP, ignore_errors=True)
    _ok("test_cleanup_test_outputs")


if __name__ == "__main__":
    print("== ZERO-APT harness dry-run tests ==")
    for fn in (test_batch_dryrun, test_single_experiment_metrics,
               test_defender_rules_on_fake_logs, test_l1_noise_reaches_monitor,
               test_fail_fast_without_key, test_cleanup_test_outputs):
        fn()
    print(f"== all {_PASS} tests passed ==")
