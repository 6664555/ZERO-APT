"""
main.py - entry point for the APT attack-defense loop.

Defines the experiment configuration, loads the action library, and calls
core.loop.run_experiment to start an experiment.

Parameterized per scenario (core/scenarios.py): round limit + Defender tier + mission goal.
Target info and environment adapters are configured entirely from environment variables /
.env (see .env.example); no lab-private information is hardcoded.

Usage:
    python main.py [S1|S2|S3|S4|S5]
"""

import os
import sys

from core.loop import run_experiment
from executor.scan_action import _load_actions, build_index
from core.state import Target_info
from core.scenarios import get_scenario
from core.interfaces import build_default_adapters
from utils.llm import connect_llm


def build_target_info():
    """Build target info from environment variables (lab IPs/credentials never enter the repo)."""
    return Target_info(
        hostname=os.getenv("TARGET_HOSTNAME", "TARGET"),
        ip_address=os.getenv("TARGET_IP", ""),
        os_version=os.getenv("TARGET_OS", "windows server 2022"),
        user_name=os.getenv("TARGET_USER", ""),
        password=os.getenv("TARGET_PASSWORD", ""),
        admin_name=os.getenv("TARGET_ADMIN_USER", "Administrator"),
        admin_password="",
    )


def main(scenario_id="S1"):
    scenario = get_scenario(scenario_id)
    if not scenario["mission"]:
        print("Error: TARGET_IP / TARGET_USER / TARGET_PASSWORD not set (see .env.example)")
        return 1

    target_info = build_target_info()
    action_lib = _load_actions()
    action_index = build_index(action_lib)  # prebuilt index to speed up filtering

    # External-dependency adapters (WinRM/ELK/snapshot/scenario init); scenario initial
    # conditions are merged into the experiment environment.
    adapters = build_default_adapters(target_info)
    init = adapters["initializer"].apply({**scenario, "id": scenario_id})
    print(f"  [Scenario] {scenario_id}: {scenario['name']} | {init.get('note', '')}")

    # Prefer an env-var mission override (experiment-specific), otherwise the scenario mission
    mission = os.getenv("MISSION") or scenario["mission"]

    state = run_experiment(
        target_info, action_lib,
        mission=mission,
        max_loops=scenario["max_loops"],
        action_index=action_index,
        api_key=None, LLM_type=os.getenv("LLM_TYPE", "deepseek"),
        defender_tier=scenario["defender_tier"],
        runner=adapters["runner"],
        log_source=adapters["log_source"],
        env_overrides=init.get("env_overrides") or None,
    )
    print(f"Experiment finished ({scenario_id}: {scenario['name']}, "
          f"Defender={scenario['defender_tier']}), {state['loop_count']} rounds, "
          f"goal achieved={state['goal_achieved']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "S1"))
