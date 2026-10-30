"""
loop.py - core module for the APT attack-defense loop: coordinates Attacker attack,
Defender defense, and the adjudication system.
"""

import copy
import json
import os
from datetime import datetime

from core.state import GlobalState
from core.archive_env import DEFAULT_ARCHIVE_ENVIRONMENT
from core.hard_filter import apply_probe_results
from agents.red import red_team
from agents.blue import blue_team
from agents.purple import purple_team_judge, purple_team_summary
from utils.logger import save_cots, save_report, save_round_logs


def generate_experiment_id():
    """Generate experiment ID: exp_YYYYMMDD_HHMMSS_ffffff (microsecond precision so batch runs in the same second don't collide)."""
    return f"exp_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"


def init_global_state(mission, max_loops, env_overrides=None):
    """Initialize every GlobalState field; env_overrides (from the scenario initializer) merge into archive_environment."""
    state = GlobalState(
        loop_count=0,
        max_loops=max_loops,
        should_continue=True,
        mission=mission,
        goal_achieved=False,
        subgoals=[],
        current_subgoal=None,
        attempted_actions_by_subgoal={},
        # deep copy: nested dicts (available_tools/open_ports/discovered_info) must not leak across experiments
        archive_environment=copy.deepcopy(DEFAULT_ARCHIVE_ENVIRONMENT),
        forbidden_actions=[],
        blue_input_logs=None,
        blue_rule_matches=[],
        red_feedback="",
        blue_feedback="",
        purple_feedback="",
        round_logs=[],
        backtracks={"total": 0, "recovered": 0, "passive_total": 0, "passive_recovered": 0},
        used_action_ids=[],
        hct_events=[],
    )
    if env_overrides:
        # Scenario initial conditions = pre-seeded environment hard conditions (reusing the
        # probe writeback mechanism: tools_unavailable / ports_unreachable / privilege, see
        # core/hard_filter.PROBE_KEYS). E.g. S5 primary-path pre-block ->
        # {"tools_unavailable": ["PsExec.exe"]} flips False, so the next round's Dispatcher
        # mechanically excludes actions depending on it, forcing the attacker to reroute.
        apply_probe_results(state["archive_environment"], env_overrides)
    return state


def run_experiment(target_info, action_lib, mission, max_loops=10,
                   action_index=None, api_key=None, LLM_type='deepseek',
                   defender_tier="L2", runner=None, log_source=None,
                   variant="full", env_overrides=None):
    """Main loop: Attacker reasoning -> Attacker action execution -> Defender detection ->
    Judge adjudication -> next round or termination.

    defender_tier: 'L1' | 'L2' | 'L3' (paper Table: defender_tiers; the caller supplies the scenario's default pairing)
    runner/log_source: external-dependency adapters (see core/interfaces.py); default impl when None
    variant: 'full' | 'actionlib_off' (-ActionLib ablation) | 'multireact_off' (-MultiReAct ablation)
    env_overrides: environment hard-condition overrides from the scenario initializer (e.g. S5 pre-block)
    """
    experiment_id = generate_experiment_id()
    state = init_global_state(mission, max_loops, env_overrides=env_overrides)
    state["experiment_id"] = experiment_id

    # startup fail-fast (blind-review C6): a real LLM run must have a key; silent degradation would produce fake results
    if LLM_type != "mock":
        key = api_key or (os.getenv("DEEPSEEK_API_KEY") if LLM_type == "deepseek"
                          else os.getenv("CLAUDE_API_KEY"))
        if not key:
            raise RuntimeError(
                f"LLM_type='{LLM_type}' needs an API key (api_key arg or env var), "
                f"see .env.example; for dry-run use LLM_type='mock'")

    while state["should_continue"]:
        r = state["loop_count"] + 1
        print(f"\n{'='*40}\n Round {r}/{max_loops} (Defender={defender_tier}, variant={variant})\n{'='*40}")
        # Attacker reasoning -> action execution (full three-layer / multireact_off single-layer ablation), Defender detection, Judge adjudication + state update
        if variant == "multireact_off":
            from agents.mono_react import mono_react_attacker
            red_feedback, red_commands = mono_react_attacker(
                state, action_lib, target_info, api_key, LLM_type, runner=runner)
        else:
            red_feedback, red_commands = red_team(
                state, action_lib, action_index, target_info, api_key, LLM_type,
                runner=runner, variant=variant
            )
        state["red_feedback"] = red_feedback
        state["red_commands"] = red_commands  # full round feedback for the Judge (paper §3.4: command sequence + exploration results)
        blue_detection = blue_team(state, action_lib, defender_tier, api_key, LLM_type, log_source=log_source)
        print(f"  [Blue] intrusion={blue_detection.get('has_intrusion')} confidence={blue_detection.get('confidence')} techniques={blue_detection.get('detected_techniques')}")
        purple_team_judge(state, target_info, api_key, LLM_type)
        print(f"  [Purple] {state['purple_feedback'][:200]}")
        state["loop_count"] += 1

        # Archive this round's logs and CoT (CTI auditability data source: paper §3.4 requires
        # recording the attacker's reasoning chain, Defender detection logic, Judge
        # adjudication basis, and backtrack triggers).
        round_log = {
            "round": state["loop_count"],
            "red_feedback": state["red_feedback"],
            "red_commands": red_commands,
            "blue_feedback": state["blue_feedback"],
            "purple_judgement": state["purple_feedback"],
            "winner": state.get("winner", ""),
            "blue_evidence_score": state.get("blue_evidence_score"),
            # deep-copy snapshots: list objects must not be polluted by later rounds (backtrack `recovered` is set after the fact)
            "hct_events": copy.deepcopy(state.get("hct_events", [])),
            "blue_rule_matches": copy.deepcopy(state.get("blue_rule_matches", [])),
            "planner_plan": copy.deepcopy(state.get("last_planner", {}).get("plan", [])),
            "planner_reasoning": state.get("last_planner", {}).get("reasoning", ""),
            "judge_reasoning": state.get("last_judge", {}).get("reasoning", ""),
            "backtrack_events": copy.deepcopy(state.get("backtrack_events", [])),
            "forbidden_actions_snapshot": list(state.get("forbidden_actions", [])),
        }
        state["round_logs"].append(round_log)
        cot_data = {
            "round": state["loop_count"],
            "red_feedback": state["red_feedback"],
            "blue_feedback": state["blue_feedback"],
            "purple_feedback": state["purple_feedback"],
            "winner": state.get("winner", ""),
            "blue_evidence_score": state.get("blue_evidence_score"),
        }
        save_cots(cot_data, experiment_id, state["loop_count"])

        # terminate on goal achieved or round limit
        if state["goal_achieved"] or state["loop_count"] >= state["max_loops"]:
            state["should_continue"] = False

    report_text = purple_team_summary(state, experiment_id, api_key, LLM_type, action_lib=action_lib)
    # CTI_FORMAT: markdown (default, .md only) / stix (.stix.json only) / both
    if os.getenv("CTI_FORMAT", "markdown").lower() != "stix":
        save_report(report_text, experiment_id)
    save_round_logs(state, experiment_id)

    return state
