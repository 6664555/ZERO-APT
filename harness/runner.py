"""harness/runner.py - batch experiment scheduler (scheme/ablation x scenario x Defender tier x repetition)

Before each experiment it calls EnvironmentResetter.reset (snapshot revert) and
ScenarioInitializer.apply (scenario initial conditions); each result is appended one line per
experiment to outputs/results/{run_id}.jsonl (directly consumable by the stats module).

Scheme mapping:
- "zero-apt"        -> variant="full"
- "actionlib_off"   -> variant="actionlib_off"   (-ActionLib ablation)
- "multireact_off"  -> variant="multireact_off"  (-MultiReAct ablation)

For range integration pass the default adapters (core.interfaces.build_default_adapters) or your
own; for dry-run acceptance pass harness.fake_adapters.build_dryrun_adapters + LLM_type='mock'.
"""

import copy
import json
import os
import time
from datetime import datetime

from core.scenarios import get_scenario
from core.interfaces import EnvironmentResetter, ScenarioInitializer
from core.loop import run_experiment

SCHEME_TO_VARIANT = {
    "zero-apt": "full",
    "actionlib_off": "actionlib_off",
    "multireact_off": "multireact_off",
}


def build_result_row(run_id, scheme, variant, scenario_id, tier, rep, state, wall, init_note, reset_ok=True):
    """Extract a result row from the experiment state (raw data; metric computation lives in harness/metrics.py)."""
    round_logs = state.get("round_logs", [])
    # only count actually-executed commands (finalize/skip empty-command entries excluded, matching metrics)
    commands = [c for rl in round_logs for c in (rl.get("red_commands") or [])
                if c.get("action") == "run_command" and c.get("command")]
    failed = [c for c in commands if c.get("status", "").startswith("failed")]
    bt = state.get("backtracks", {})
    return {
        "run_id": run_id,
        "scheme": scheme,
        "variant": variant,
        "scenario": scenario_id,
        "defender_tier": tier,
        "rep": rep,
        "experiment_id": state.get("experiment_id", ""),
        "goal_achieved": bool(state.get("goal_achieved")),
        "reset_ok": bool(reset_ok),
        "rounds": state.get("loop_count", 0),
        "max_loops": state.get("max_loops", 0),
        "wall_seconds": round(wall, 2),
        "init_note": init_note,
        "commands_total": len(commands),
        "commands_failed": len(failed),
        "hct_total": sum(e.get("hct_count", 0) for e in state.get("hct_events", [])),
        "rule_match_total": sum(len(rl.get("blue_rule_matches", [])) for rl in round_logs),
        "backtracks": bt,
        "used_action_ids": state.get("used_action_ids", []),
        "winner_history": [rl.get("winner") for rl in round_logs],
        "evidence_scores": [rl.get("blue_evidence_score") for rl in round_logs],
    }


def run_batch(plan, target_info, action_lib, action_index, api_key=None, LLM_type='deepseek',
              runner=None, log_source=None, resetter=None, initializer=None,
              out_dir="outputs/results", mission_override=None):
    """Batch scheduler.

    plan: {
        "schemes":   ["zero-apt", ...],
        "scenarios": ["S1", ...],
        "tiers":     ["L1", "L2", "L3"],
        "reps":      int,
    }
    mission_override: optional dict {scenario_id: mission text} (experiment-specific mission descriptions).
    Returns {"run_id", "out_path", "rows"}.
    """
    resetter = resetter or _import_default_resetter()
    initializer = initializer or _import_default_initializer()

    run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{run_id}.jsonl")
    rows = []

    for scheme in plan["schemes"]:
        if scheme not in SCHEME_TO_VARIANT:
            raise ValueError(f"unknown scheme '{scheme}', available: {list(SCHEME_TO_VARIANT)}")
        variant = SCHEME_TO_VARIANT[scheme]
        for sid in plan["scenarios"]:
            sc = get_scenario(sid)
            for tier in plan["tiers"]:
                for rep in range(1, plan["reps"] + 1):
                    reset_ok = resetter.reset(sid)
                    init = initializer.apply({**sc, "id": sid})
                    mission = (mission_override or {}).get(sid) or sc["mission"]
                    # independent target_info copy per experiment: Judge-written credentials must not leak across reps
                    ti = copy.deepcopy(target_info)
                    t0 = time.time()
                    state = run_experiment(
                        ti, action_lib,
                        mission=mission,
                        max_loops=sc["max_loops"],
                        action_index=action_index,
                        api_key=api_key, LLM_type=LLM_type,
                        defender_tier=tier,
                        runner=runner, log_source=log_source,
                        variant=variant,
                        env_overrides=init.get("env_overrides") or None,
                    )
                    wall = time.time() - t0
                    row = build_result_row(run_id, scheme, variant, sid, tier, rep, state,
                                           wall, init.get("note", ""), reset_ok=reset_ok)
                    with open(out_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(row, ensure_ascii=False) + "\n")
                    rows.append(row)
                    print(f"  [harness] {scheme}/{sid}/{tier}/rep{rep}: "
                          f"goal={row['goal_achieved']} rounds={row['rounds']} "
                          f"cmds={row['commands_total']} failed={row['commands_failed']} "
                          f"hct={row['hct_total']} wall={wall:.1f}s")

    return {"run_id": run_id, "out_path": out_path, "rows": rows}


def _import_default_resetter() -> EnvironmentResetter:
    from core.interfaces import DefaultEnvironmentResetter
    return DefaultEnvironmentResetter()


def _import_default_initializer() -> ScenarioInitializer:
    from core.interfaces import DefaultScenarioInitializer
    return DefaultScenarioInitializer()
