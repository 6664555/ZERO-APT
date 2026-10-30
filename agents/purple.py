"""
purple.py - Judge module.
Judge (per-round adjudication: score the Defender's evidence / decide the winner) and
Summary (post-hoc CTI report generation after the experiment ends).
"""

import json
import os

from agents.prompts.judge import JUDGE_PROMPT
from agents.prompts.summary import SUMMARY_PROMPT
from utils.llm import connect_llm_json, connect_llm
from core.judge_rules import adjudicate
from core.hard_filter import apply_probe_results


def purple_team_judge(state, target_info, api_key=None, LLM_type='deepseek'):
    """Judge: fill JUDGE_PROMPT, call the LLM to adjudicate, update environment state, and return the verdict."""
    prompt = JUDGE_PROMPT.format(
        red_feedback=state["red_feedback"],
        red_commands=json.dumps(state.get("red_commands", []), ensure_ascii=False),
        blue_feedback=state["blue_feedback"],
        archive_environment=json.dumps(state["archive_environment"]),
        discovered_info=json.dumps(
            state["archive_environment"].get("discovered_info", {})
        ),
        forbidden_actions_str=json.dumps(state["forbidden_actions"]),
        target_info_str=json.dumps(target_info),
    )
    judge_result = connect_llm_json(prompt, api_key, LLM_type)
    # paper §3.4: the winner is decided by mechanically comparing blue_evidence_score against
    # threshold 75; the LLM's winner field is only a cross-check, and on mismatch the score wins.
    score = judge_result.get("blue_evidence_score")
    derived = adjudicate(score)
    if judge_result.get("winner") != derived:
        print(f"  [Judge] score={score} -> {derived} (LLM winner '{judge_result.get('winner')}' overridden)")
    judge_result["winner"] = derived
    state["winner"] = derived
    state["blue_evidence_score"] = score
    state["last_judge"] = {"reasoning": judge_result.get("reasoning", ""),
                           "observation": judge_result.get("observation", "")}
    _apply_judge_result(state, judge_result, target_info)
    state["purple_feedback"] = judge_result.get("observation", "")
    return judge_result


def _apply_judge_result(state, judge_result, target_info):
    """Update discovered_info and forbidden_actions based on the winner branch.

    Discoveries accumulate (paper: reconnaissance discoveries persist across rounds; an empty
    update must not overwrite historical discoveries)."""
    winner = judge_result.get("winner", "")
    env_update = judge_result.get("environment_update") or {}
    if not isinstance(env_update, dict):
        env_update = {}

    # Attacker wins: write this round's discovered files/credentials/other into environment state
    if winner == "red_win":
        discovered = state["archive_environment"].setdefault("discovered_info", {})
        for f in env_update.get("files_found") or []:
            if f not in discovered.setdefault("files_found", []):
                discovered["files_found"].append(f)
        existing_users = {c.get("username") for c in discovered.setdefault("credentials", [])
                          if isinstance(c, dict)}
        for cred in env_update.get("credentials") or []:
            if isinstance(cred, dict) and cred.get("username") not in existing_users:
                discovered["credentials"].append(cred)
        if isinstance(env_update.get("other"), dict):
            discovered.setdefault("other", {}).update(env_update["other"])
        for cred in discovered.get("credentials", []):
            if isinstance(cred, dict) and cred.get("username") == "Administrator":
                target_info["admin_password"] = cred.get("password", "")
                # admin credentials obtained -> raise the environment hard condition current_privilege (raise-only)
                apply_probe_results(state["archive_environment"], {"privilege": "admin"})
                break

    # Defender wins: no environment update is written; the Attacker's results do not enter the environment.

    # Regardless of winner: append this round's newly forbidden actions to state
    for item in env_update.get("forbidden_actions", []):
        if isinstance(item, dict):
            action_id = item.get("action_id", "")
        else:
            action_id = str(item)
        if action_id and action_id not in state["forbidden_actions"]:
            state["forbidden_actions"].append(action_id)


def purple_team_summary(state, experiment_id, api_key=None, LLM_type='deepseek', action_lib=None):
    """Judge reporter: fill SUMMARY_PROMPT to generate the CTI-format Markdown report; optionally export STIX based on CTI_FORMAT."""
    prompt = SUMMARY_PROMPT.format(
        mission=state["mission"],
        round_logs_str=json.dumps(
            state["round_logs"], ensure_ascii=False, indent=2
        ),
    )
    prompt += f"\n\n## Additional Info\nExperiment ID: {experiment_id}"
    report = connect_llm(prompt, api_key, LLM_type)
    _maybe_export_stix(state, experiment_id, action_lib)
    return report or ""


def _maybe_export_stix(state, experiment_id, action_lib=None):
    """When CTI_FORMAT=stix|both, additionally export a STIX 2.1 bundle (requires pip install stix2)."""
    if os.getenv("CTI_FORMAT", "markdown").lower() not in ("stix", "both"):
        return
    try:
        from harness.stix_export import build_stix_bundle
        from utils.logger import save_stix_bundle
        bundle = build_stix_bundle(state, action_lib=action_lib)
        path = save_stix_bundle(bundle, experiment_id)
        print(f"  [Summary] STIX bundle written -> {path}")
    except ImportError as e:
        print(f"  [Summary] stix2 not installed, STIX export skipped (pip install stix2) — {e}")
