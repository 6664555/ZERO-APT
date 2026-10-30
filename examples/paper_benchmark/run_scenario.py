"""examples/paper_benchmark/run_scenario.py — run a single scenario for real (not mock)

Usage (from the repository root Zero-APT-Code/):
    # 1) offline wiring check first (never touches the range / network)
    python examples/paper_benchmark/run_scenario.py S5 --check
    # 2) after filling config.yaml + env vars (.env), run for real
    python examples/paper_benchmark/run_scenario.py S5

A real run needs: DEEPSEEK_API_KEY + TARGET_PASSWORD + ELASTICSEARCH_URL + the range online.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _HERE)         # make `from adapters import ...` work
sys.path.insert(0, _REPO_ROOT)    # make `from core/executor/...` work

from core.state import Target_info
from core.scenarios import get_scenario
from core.loop import run_experiment
from executor.scan_action import _load_actions, build_index
from adapters import PaperCommandRunner, PaperLogSource, PaperEnvironmentResetter, PaperScenarioInitializer


def load_config(path):
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_target_info(cfg):
    t = cfg["targets"]["primary"]
    password = os.getenv(t["initial_password_env"], "")
    return Target_info(
        hostname=t["hostname"], ip_address=t["ip"], os_version=t["os"],
        user_name=t["initial_user"], password=password,
        admin_name=t["admin_user"], admin_password="",
    )


def build_adapters(cfg, target_info):
    lateral = cfg["targets"]["lateral"]
    runner = PaperCommandRunner(target_info, host_registry={lateral["hostname"]: lateral["ip"]})
    log_source = PaperLogSource(elk_url=os.getenv(cfg["defender"]["elk_url_env"], ""),
                                index=cfg["defender"].get("index", "winlogbeat-*"))
    resetter = PaperEnvironmentResetter(cfg.get("reset", {}))
    initializer = PaperScenarioInitializer(lateral_ip=lateral["ip"])
    return {"runner": runner, "log_source": log_source,
            "resetter": resetter, "initializer": initializer}


def main():
    args = [a for a in sys.argv[1:]]
    check_only = "--check" in args
    sid = next((a for a in args if not a.startswith("--")), None) or "S1"

    cfg = load_config(os.path.join(_HERE, "config.yaml"))
    sc = get_scenario(sid)
    target_info = build_target_info(cfg)
    adapters = build_adapters(cfg, target_info)
    init = adapters["initializer"].apply({**sc, "id": sid})

    print(f"[config] scenario {sid}: {sc['name']} | tier {sc['defender_tier']} | round cap {sc['max_loops']}")
    print(f"[config] primary target {target_info['hostname']} ({target_info['ip_address']})")
    print(f"[config] scenario init: {init['note']}")
    print(f"[config] env pre-seed (hard-condition flip): {init['env_overrides']}")

    if check_only:
        # only verify wiring; never call the LLM / range
        if not target_info["password"]:
            print("[check] [!] TARGET_PASSWORD not set (needed before a real run)")
        print("[check] adapter wiring verified (run_scenario did not run a real experiment)")
        return 0

    # real run: a missing key fails fast at run_experiment startup
    action_lib = _load_actions()
    action_index = build_index(action_lib)
    state = run_experiment(
        target_info, action_lib,
        mission=sc["mission"],
        max_loops=sc["max_loops"],
        action_index=action_index,
        LLM_type=cfg["llm"]["type"],
        defender_tier=sc["defender_tier"],
        runner=adapters["runner"],
        log_source=adapters["log_source"],
        env_overrides=init.get("env_overrides") or None,
    )
    print(f"[done] {sid} goal_achieved={state['goal_achieved']} rounds={state['loop_count']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
