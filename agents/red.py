# -*- coding: utf-8 -*-
"""red.py - Attacker module: 4-layer LLM pipeline"""

import json, re
from agents.prompts.planner import PLANNER_PROMPT
from agents.prompts.dispatcher import DISPATCHER_PROMPT, DISPATCHER_P2_PROMPT
from agents.prompts.executor import EXECUTOR_PROMPT
from utils.llm import connect_llm_json
from core.state import GlobalState, RedTeamInternalState, Target_info
from core.hard_filter import filter_actions, apply_probe_results, PROBE_KEYS
from core.interfaces import CommandRunner, DefaultCommandRunner

def _format_env_for_prompt(state):
    """Filter non-None archive values for prompt"""
    env = state.get("archive_environment", {})
    parts = []
    for key, value in env.items():
        if key == "discovered_info": continue
        if value is not None: parts.append(f"{key}: {value}")
    return "\n".join(parts)

def _format_action_lib_str(action_lib, forbidden=None):
    """Compress to Txxx: name, exclude forbidden"""
    fb_set = set(forbidden or [])
    out = []
    for act in action_lib:
        aid = act.get("action_id", "")
        if aid in fb_set: continue
        out.append(f"{aid}: {act.get('display_name','')}")
    return "\n".join(out)

def _format_selected_actions_str(selected_actions):
    """Full action dict list to JSON string"""
    return json.dumps(selected_actions, ensure_ascii=False, indent=2)

def _normalize_attack_plan(ap):
    """Normalize AttackPlan to [{sc, reasoning, max_retries}]
    Tolerate LLM shape drift: a single-step dict (rather than a list) is auto-wrapped."""
    if isinstance(ap, dict):
        ap = [ap]
    steps = []
    for sd in ap:
        if not isinstance(sd, dict):
            continue
        content = ""
        for k in sd:
            if re.match(r"^step\d+$", k): content = sd[k]; break
        steps.append({"step_content": content,
            "reasoning": sd.get("reasoning", ""),
            "max_retries": sd.get("max_retries", 3)})
    return steps
def _format_current_credentials(target_info):
    """Format the current login credentials for the executor prompt."""
    privilege = "admin" if target_info.get("admin_password") else "user"
    lines = [
        f"current target IP: {target_info.get('ip_address','unknown')}",
        f"current user: {target_info.get('user_name','unknown')} (privilege: {privilege})",
    ]
    if target_info.get("admin_password"):
        lines.append(f"admin credentials available: {target_info.get('admin_name','Administrator')}")
    return "\n".join(lines)
def _split_probes(disc):
    """Split Executor discoveries: reserved keys -> hard-condition probes (written back to env), the rest -> soft conditions."""
    probes = {k: disc[k] for k in PROBE_KEYS if k in disc}
    soft = {k: v for k, v in disc.items() if k not in PROBE_KEYS}
    return probes, soft
def red_team_planner(state, pending_feedback="", api_key=None, LLM_type="deepseek"):
    """Planner LLM: create/adjust subgoal plan"""
    ae = state.get("archive_environment", {})
    di = ae.get("discovered_info", {})
    prompt = PLANNER_PROMPT.format(
        mission=state.get("mission", ""),
        environment=_format_env_for_prompt(state),
        discovered_info=json.dumps(di, ensure_ascii=False),
        observation=state.get("purple_feedback") or "",
        plan=json.dumps(state.get("subgoals", []), ensure_ascii=False),
        current_subgoal=state.get("current_subgoal") or "None",
        forbidden_actions_str=json.dumps(state.get("forbidden_actions", []), ensure_ascii=False),
        pending_feedback=pending_feedback)
    result = connect_llm_json(prompt, api_key, LLM_type)
    return {"plan": result.get("plan", state.get("subgoals", [])),
            "current_subgoal": result.get("current_subgoal", state.get("current_subgoal")),
            "reasoning": result.get("reasoning", ""),
            "goal_achieved": result.get("goal_achieved", False)}
def _dispatcher_p2(ae, efp, subgoal, selected_actions_str, api_key, LLM_type):
    """Dispatcher Phase 2 common tail: orchestrate the mini plan (full action JSON, or the ablation's empty candidate set)."""
    p2 = DISPATCHER_P2_PROMPT.format(
        subgoal=subgoal,
        selected_actions_str=selected_actions_str,
        discovered_info=json.dumps(ae.get("discovered_info", {}), ensure_ascii=False),
        archive_environment=json.dumps(efp, ensure_ascii=False))
    print(f"  [Dispatcher] P2 prompt len={len(p2)}")
    r2 = connect_llm_json(p2, api_key, LLM_type)
    if "_raw" in r2: return {"needs_feedback": True, "feedback_reason": "P2 parse failed"}
    print(f"  [Dispatcher] P2 resp: keys={list(r2.keys())} dp={r2.get('despatcher_plan','?')} fb={str(r2.get('feedback_reason',''))[:100]}")
    dp = str(r2.get("despatcher_plan", "")).lower()  # tolerate the LLM returning a boolean
    if dp in ("false", "flase"):
        fb = r2.get("feedback_reason") or "P2: cannot form mini plan from selected actions"
        return {"needs_feedback": True, "feedback_reason": fb}
    ap = r2.get("AttackPlan", [])
    if not ap: return {"needs_feedback": True, "feedback_reason": "AttackPlan is empty"}
    return _normalize_attack_plan(ap)


def red_team_dispatcher(state, action_lib, action_index, api_key=None, LLM_type="deepseek", variant="full"):
    """Dispatcher(Builder): two-phase action selection + mini plan

    variant='full'           : paper's full mechanism (mechanical hard-constraint filtering + two phases)
    variant='actionlib_off'  : -ActionLib ablation (paper Table: ablation) — library removed,
                               LLM generates commands from memory, keeping multi-layer planning +
                               Judge closure; no mechanical filtering.
    """
    ae = state.get("archive_environment", {})
    efp = {k: v for k, v in ae.items() if v is not None}
    forbidden = state.get("forbidden_actions", [])
    subgoal = state.get("current_subgoal", "")

    if variant == "actionlib_off":
        state.setdefault("hct_events", []).append(
            {"round": state.get("loop_count", 0) + 1, "blocked": {}, "hct_count": 0})
        print("  [Dispatcher] -ActionLib ablation: action library disabled")
        return _dispatcher_p2(ae, efp, subgoal,
                              "(action library disabled in this ablation: generate commands from your knowledge)",
                              api_key, LLM_type)

    # Mechanical hard-constraint filtering (paper §3.3): preconditions matched against environment
    # state in code, not by LLM judgment. No feasible action -> trigger active backtrack directly
    # (skipping the P1 LLM call).
    feasible, blocked_reasons, hct = filter_actions(action_lib, ae, forbidden)
    state.setdefault("hct_events", []).append(
        {"round": state.get("loop_count", 0) + 1, "blocked": blocked_reasons, "hct_count": hct})
    print(f"  [Dispatcher] hard-filter: {len(feasible)}/{len(action_lib)} feasible, hct={hct}")
    if not feasible:
        return {"needs_feedback": True,
                "feedback_reason": "No action satisfies hard preconditions under current environment state (mechanical filter)"}

    # Phase 1: filter action_ids from index
    p1 = DISPATCHER_PROMPT.format(
        plan=json.dumps(state.get("subgoals", []), ensure_ascii=False),
        subgoal=subgoal,
        action_lib_str=_format_action_lib_str(feasible),
        selected_actions_str="",
        archive_environment=json.dumps(efp, ensure_ascii=False),
        discovered_info=json.dumps(ae.get("discovered_info", {}), ensure_ascii=False),
        forbidden_actions_str=json.dumps(forbidden, ensure_ascii=False))
    r1 = connect_llm_json(p1, api_key, LLM_type)
    if "_raw" in r1: return {"needs_feedback": True, "feedback_reason": "P1 parse failed"}
    if r1.get("needs_feedback", False):
        fb = r1.get("feedback_reason") or "P1 LLM returned needs_feedback=true (no reason given)"
        return {"needs_feedback": True, "feedback_reason": fb}

    # Collect selected action_ids from the response (tolerate LLM shape drift:
    # string ID / {action_id: str} / {action_id: [..]} / bare dict / bare list)
    raw_sel = r1.get("selected_actions", [])
    if isinstance(raw_sel, dict):
        raw_sel = [raw_sel]
    if not isinstance(raw_sel, list):
        raw_sel = []
    all_ids = []
    for entry in raw_sel:
        if isinstance(entry, str):
            all_ids.append(entry)
            continue
        if not isinstance(entry, dict):
            continue
        ids = entry.get("action_id", [])
        if isinstance(ids, list):
            all_ids.extend([i for i in ids if isinstance(i, str)])
        elif isinstance(ids, str):
            all_ids.append(ids)
    seen = set()
    uids = [a for a in all_ids if not (a in seen or seen.add(a))]
    print(f"  [Dispatcher] P1 selected: {uids}")
    # Mechanical re-check (paper's system-level guarantee): IDs returned by P1 resolve only inside
    # the mechanically-filtered feasible set, so a hallucinated action that was hard-constraint-excluded
    # or Judge-forbidden cannot enter P2.
    feasible_index = {a["action_id"]: a for a in feasible}
    sel_full = [feasible_index[aid] for aid in uids if aid in feasible_index]
    missed = [aid for aid in uids if aid not in feasible_index]
    if missed: print(f"  [Dispatcher] P1 IDs rejected by mechanical filter: {missed}")
    valid_uids = [a["action_id"] for a in sel_full]
    state.setdefault("used_action_ids", []).extend(valid_uids)
    if not sel_full: return {"needs_feedback": True, "feedback_reason": f"None of {uids} passes the mechanical precondition filter"}

    # Phase 2: orchestrate mini plan with full action details (dedicated P2 prompt)
    return _dispatcher_p2(ae, efp, subgoal, _format_selected_actions_str(sel_full), api_key, LLM_type)
def red_team_executor(state, mini_plan_steps, target_info, api_key=None, LLM_type="deepseek", runner=None):
    """Executor ReAct loop: execute mini plan step by step, driven by LLM completed_steps"""
    runner = runner or DefaultCommandRunner(target_info)
    ae = state.get("archive_environment", {})
    di = ae.get("discovered_info", {})
    current_creds = _format_current_credentials(target_info)
    ri = RedTeamInternalState(mini_plan_steps=mini_plan_steps, current_step_index=0,
        local_environment_cache=di.copy(), executed_commands=[], last_command=None, last_output=None,
        retry_count=0, max_retries=3, analysis_feedback="")
    total = len(mini_plan_steps)

    while ri["current_step_index"] < total:
        sidx = ri["current_step_index"]
        step = mini_plan_steps[sidx]
        try:
            smr = int(step.get("max_retries", 3))  # tolerate the LLM returning a string / missing value
        except (TypeError, ValueError):
            smr = 3
        ri["retry_count"] = 0; action = ""; stall = 0

        while ri["retry_count"] <= smr:
            el = []
            for ec in ri["executed_commands"]:
                el.append("Step {}: Cmd: {} | Out: {} | Status: {}".format(
                    ec.get("step","?"), ec.get("command",""),
                    ec.get("output",""), ec.get("status","")))
            e_str = "\n\n".join(el)

            prompt = EXECUTOR_PROMPT.format(
                mini_plan_str=json.dumps(mini_plan_steps, ensure_ascii=False),
                step_id=sidx + 1,
                executed_commands_str=e_str or "No commands executed yet",
                local_environment_cache=json.dumps(ri["local_environment_cache"], ensure_ascii=False),
                current_credentials_str=current_creds,
                discovered_info_str=json.dumps(di, ensure_ascii=False),
                max_retries=smr)
            lr = connect_llm_json(prompt, api_key, LLM_type)
            if "_raw" in lr: ri["retry_count"] += 1; continue

            action = lr.get("action", "")
            cmd = lr.get("command", "")

            if action == "finalize":
                ri["analysis_feedback"] = lr.get("analysis_feedback", "")
                ri["executed_commands"].append({"step": sidx+1, "action": "finalize",
                    "command": "", "output": "", "status": "finalized"})
                disc = lr.get("discoveries", {})
                if disc and isinstance(disc, dict):
                    # reserved keys -> hard-condition probe writeback (paper's three-step loop, step 2), the rest -> soft conditions
                    probes, soft = _split_probes(disc)
                    if probes:
                        changed = apply_probe_results(ae, probes)
                        if changed:
                            print(f"  [Executor] hard-condition probes -> {changed}")
                    if soft:
                        ri["local_environment_cache"].update(soft)
                        ae.setdefault("discovered_info", {}).update(soft)
                ri["current_step_index"] = total; break

            elif action == "run_command" and cmd:
                exe = lr.get("executor", "powershell")
                target_ip = lr.get("target_ip", "").strip()
                target_user = lr.get("target_user", "").strip()
                target_pass = lr.get("target_password", "").strip()
                output = ""; code = -1
                try:
                    if exe == "cmd":
                        output, code = runner.run_cmd(cmd, target_ip=target_ip, user=target_user, password=target_pass)
                    else:
                        output, code = runner.run_ps(cmd, target_ip=target_ip, user=target_user, password=target_pass)
                except Exception as e: output = "[ExecError] " + str(e); code = -1

                ri["executed_commands"].append({"step": sidx+1, "action": "run_command",
                    "command": cmd, "output": output[:500],
                    "status": "success" if code == 0 else "failed(code={})".format(code)})
                ri["last_command"] = cmd; ri["last_output"] = output

                disc = lr.get("discoveries", {})
                if disc and isinstance(disc, dict):
                    # reserved keys -> hard-condition probe writeback (paper's three-step loop, step 2), the rest -> soft conditions
                    probes, soft = _split_probes(disc)
                    if probes:
                        changed = apply_probe_results(ae, probes)
                        if changed:
                            print(f"  [Executor] hard-condition probes -> {changed}")
                    if soft:
                        ri["local_environment_cache"].update(soft)
                        ae.setdefault("discovered_info", {}).update(soft)

                # advance steps driven by the LLM's completed_steps
                completed = lr.get("completed_steps", [])
                if (sidx + 1) in completed:
                    ri["current_step_index"] += 1; break
                elif code != 0:
                    ri["retry_count"] += 1
                # code==0 but the LLM did not mark complete: continue iterating on the current step, with a stall cap to avoid infinite loops
                else:
                    stall += 1
                    if stall > smr:
                        ri["current_step_index"] += 1; break
            elif action == "skip":
                # paper: the LLM autonomously decides to skip this step (not applicable / low value), not to abandon the whole plan
                ri["executed_commands"].append({"step": sidx+1, "action": "skip",
                    "command": "", "output": "", "status": "skipped"})
                ri["analysis_feedback"] = lr.get("analysis_feedback", "")
                ri["current_step_index"] += 1; break
            else: ri["retry_count"] += 1

        if ri["retry_count"] > smr: ri["current_step_index"] += 1; continue
        if action == "finalize": break

    return (ri["analysis_feedback"] or "Execution completed", ri["executed_commands"])
def red_team(state, action_lib, action_index, target_info, api_key=None, LLM_type="deepseek", runner=None, variant="full"):
    """Orchestrator: Planner->Dispatcher->Executor, max 3 backtracks

    variant='full' | 'actionlib_off' (-ActionLib ablation, see red_team_dispatcher).
    Backtrack instrumentation (BSR metric source):
    - total/recovered      : active backtrack (Dispatcher-triggered, same-round reroute)
    - passive_total/...    : passive backtrack (previous round ruled Defender-win, this round Planner reroutes)
    """
    state.setdefault("subgoals", [])
    state.setdefault("current_subgoal", None)
    state.setdefault("goal_achieved", False)
    state.setdefault("archive_environment", {}).setdefault("discovered_info", {})
    bt = state.setdefault("backtracks", {"total": 0, "recovered": 0,
                                         "passive_total": 0, "passive_recovered": 0})
    events = state.setdefault("backtrack_events", [])
    passive = state.get("winner") == "blue_win"  # previous round detected by Defender -> this round is a passive backtrack
    if passive:
        bt["passive_total"] += 1
        events.append({"round": state.get("loop_count", 0) + 1, "type": "passive",
                       "reason": "previous round ruled blue_win (Judge-driven replan)",
                       "recovered": False})
    mini_plan = None; last_fb = ""; fb_count = 0

    for pt in range(3):
        pr = red_team_planner(state, pending_feedback=last_fb, api_key=api_key, LLM_type=LLM_type)
        state["subgoals"] = pr["plan"]
        state["current_subgoal"] = pr.get("current_subgoal")
        state["goal_achieved"] = pr.get("goal_achieved", False)
        state["last_planner"] = {"plan": pr["plan"], "reasoning": pr.get("reasoning", ""),
                                 "current_subgoal": pr.get("current_subgoal")}
        print(f"  [Planner] plan={pr['plan']} subgoal={pr['current_subgoal']} goal_achieved={pr['goal_achieved']} reasoning={pr.get('reasoning','')[:120]}")
        if state["goal_achieved"]:
            if passive:
                bt["passive_recovered"] += 1
                pending = [e for e in events if e["type"] == "passive" and not e["recovered"]]
                if pending:
                    pending[-1]["recovered"] = True
            mini_plan = []; break

        dr = red_team_dispatcher(state, action_lib, action_index, api_key=api_key, LLM_type=LLM_type, variant=variant)
        if isinstance(dr, dict) and dr.get("needs_feedback"):
            print(f"  [Dispatcher] needs_feedback: {dr.get('feedback_reason','')[:120]}")
            fb_count += 1
            bt["total"] += 1
            events.append({"round": state.get("loop_count", 0) + 1, "type": "active",
                           "reason": str(dr.get("feedback_reason", ""))[:200], "recovered": False})
            last_fb = dr.get("feedback_reason", ""); continue
        mini_plan = dr
        if fb_count:
            bt["recovered"] += 1
            # the most recent active backtrack recovered via the subsequent successful replan
            pending = [e for e in events if e["type"] == "active" and not e["recovered"]]
            if pending:
                pending[-1]["recovered"] = True
        for i, s in enumerate(mini_plan):
            print(f"  [Dispatcher] step{i+1}: {s.get('step_content','')[:100]} ({s.get('reasoning','')[:80]})")
        break
    else:
        fb = "All 3 backtrack attempts failed."
        state["red_feedback"] = fb; return (fb, [])

    fb, cmds = red_team_executor(state, mini_plan, target_info, api_key=api_key, LLM_type=LLM_type, runner=runner)
    state["red_feedback"] = fb
    print(f"  [Executor] {fb[:200]}")
    return (fb, cmds)
