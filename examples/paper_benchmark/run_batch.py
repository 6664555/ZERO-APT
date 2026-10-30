"""examples/paper_benchmark/run_batch.py — real batch run of the paper experiment matrix (not mock)

Key point: the 1,400 experiments are not a hardcoded script — they are one way to fill the plan
dict. Change this plan and it becomes your own experiment.

Usage (from the repository root Zero-APT-Code/):
    python examples/paper_benchmark/run_batch.py --check      # wiring check only
    python examples/paper_benchmark/run_batch.py              # real batch (needs range + key)

Results are appended one line per experiment to outputs/results/{run_id}.jsonl; metrics/stats use
harness/metrics.py + stats.py.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _HERE)
sys.path.insert(0, _REPO_ROOT)

from run_scenario import load_config, build_target_info, build_adapters
from executor.scan_action import _load_actions, build_index
from harness.runner import run_batch

# Paper §4: 5 scenarios x 4 schemes x 3 tiers x 20 reps = 1,200 (core) + 5x2x20 = 200 (ablations).
# The three baseline schemes (aurora/pentestgpt/claude_code) are maintained separately (by the
# senior author); this runs only our three schemes. To reproduce the matrix, raise reps to 20,
# expand scenarios to S1-S5, and tiers to L1-L3.
PLAN = {
    "schemes": ["zero-apt", "actionlib_off", "multireact_off"],
    "scenarios": ["S1"],
    "tiers": ["L2"],
    "reps": 1,
}


def main():
    check_only = "--check" in sys.argv
    cfg = load_config(os.path.join(_HERE, "config.yaml"))
    target_info = build_target_info(cfg)
    adapters = build_adapters(cfg, target_info)
    action_lib = _load_actions()
    action_index = build_index(action_lib)

    print(f"[plan] {PLAN}")

    if check_only:
        init = adapters["initializer"].apply({"id": "S5", "name": "", "defender_tier": "L1"})
        print(f"[check] S5 init: {init}")
        print("[check] batch wiring verified (no real experiment ran)")
        return 0

    result = run_batch(
        PLAN, target_info, action_lib, action_index,
        LLM_type=cfg["llm"]["type"],
        runner=adapters["runner"], log_source=adapters["log_source"],
        resetter=adapters["resetter"], initializer=adapters["initializer"],
    )
    print(f"[done] result: {result['out_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
