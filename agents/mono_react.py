"""agents/mono_react.py - -MultiReAct ablation variant (paper Table: ablation)

Merges Planner + Dispatcher + Executor into a single-layer ReAct and removes the Judge closure,
keeping the action library. Key differences from the full mechanism (the ablation target):
- No planning/execution separation: one LLM decides both "what to do" and "how to execute"
- No mechanical hard-constraint filtering (the filter goes away with the Dispatcher layer): the action library is reference text only
- No structured backtracking: failures only retry within this layer, never triggering Planner reroute
The Judge still adjudicates each round (game rules unchanged), but its feedback no longer enters
the attacker's decision loop.
"""

import json

from utils.llm import connect_llm_json
from core.interfaces import CommandRunner, DefaultCommandRunner

MONO_REACT_PROMPT = """You are the MonoReAct attacker, a single-layer ReAct agent (ablation variant).
You plan AND execute in one loop: think, run a command, observe, adjust.

## Mission
{mission}

## Current environment (archive_environment)
{archive_environment}

## Discovered information (discovered_info)
{discovered_info}

## Forbidden actions (forbidden_actions)
{forbidden_actions}

## Action library (reference only, no mechanical filtering)
{action_lib_str}

## Executed commands and results so far
{executed_commands}

Return a pure JSON object:
```json
{{
  "thought": "Analyze the current situation and decide what to do next",
  "action": "run_command | finalize",
  "command": "Specific powershell or cmd command (empty if finalize)",
  "executor": "powershell | cmd",
  "target_ip": "Lateral movement target IP, leave empty if executing on current machine",
  "target_user": "Lateral movement target username, used together with target_ip, otherwise leave empty",
  "target_password": "Lateral movement target password, used together with target_ip, otherwise leave empty",
  "discoveries": {{"Discovered parameter key": "value"}},
  "analysis_feedback": "Summary analysis (mandatory when finalize)",
  "goal_achieved": false
}}
```

Rules:
1. Commands must be executable on the remote Windows Server 2022 target
2. If the mission is complete, set action to finalize AND goal_achieved to true; if the path is dead, finalize with goal_achieved false
3. Record confirmed new facts (file paths, credentials) in discoveries
"""


def _format_action_names(action_lib, forbidden):
    fb_set = set(forbidden or [])
    out = []
    for act in action_lib or []:
        aid = act.get("action_id", "")
        if aid in fb_set:
            continue
        out.append(f"{aid}: {act.get('display_name', '')}")
    return "\n".join(out)


def mono_react_attacker(state, action_lib, target_info, api_key=None, LLM_type="deepseek",
                        runner=None, max_iterations=5):
    """Single-layer ReAct attacker: at most max_iterations think-execute iterations per round.

    Returns (analysis_feedback, executed_commands), matching red_team's return shape.
    """
    runner = runner or DefaultCommandRunner(target_info)
    ae = state.get("archive_environment", {})
    executed = []
    last_fb = "MonoReAct execution completed (no iterations)"

    for _ in range(max_iterations):
        prompt = MONO_REACT_PROMPT.format(
            mission=state.get("mission", ""),
            archive_environment=json.dumps({k: v for k, v in ae.items() if v is not None}, ensure_ascii=False),
            discovered_info=json.dumps(ae.get("discovered_info", {}), ensure_ascii=False),
            forbidden_actions=json.dumps(state.get("forbidden_actions", []), ensure_ascii=False),
            action_lib_str=_format_action_names(action_lib, state.get("forbidden_actions", [])),
            executed_commands=json.dumps(executed, ensure_ascii=False) if executed else "No commands executed yet",
        )
        lr = connect_llm_json(prompt, api_key, LLM_type)
        if "_raw" in lr:
            lr = {"action": "finalize", "analysis_feedback": "MonoReAct: response parse failed, aborting round"}

        action = lr.get("action", "")
        if action == "finalize":
            last_fb = lr.get("analysis_feedback", "MonoReAct finalized")
            # the ablation also emits goal_achieved (otherwise ASR would be 0 and couldn't be compared with the paper's ablation table)
            state["goal_achieved"] = bool(lr.get("goal_achieved", False))
            executed.append({"step": len(executed) + 1, "action": "finalize",
                             "command": "", "output": "", "status": "finalized"})
            break
        elif action == "run_command" and lr.get("command"):
            cmd = lr.get("command", "")
            exe = lr.get("executor", "powershell")
            target_ip = lr.get("target_ip", "").strip()
            target_user = lr.get("target_user", "").strip()
            target_pass = lr.get("target_password", "").strip()
            try:
                if exe == "cmd":
                    output, code = runner.run_cmd(cmd, target_ip=target_ip, user=target_user, password=target_pass)
                else:
                    output, code = runner.run_ps(cmd, target_ip=target_ip, user=target_user, password=target_pass)
            except Exception as e:
                output, code = "[ExecError] " + str(e), -1
            executed.append({"step": len(executed) + 1, "action": "run_command",
                             "command": cmd, "output": output[:500],
                             "status": "success" if code == 0 else f"failed(code={code})"})
            last_fb = lr.get("analysis_feedback", "")
            disc = lr.get("discoveries", {})
            if disc and isinstance(disc, dict):
                ae.setdefault("discovered_info", {}).update(disc)
        else:
            last_fb = "MonoReAct: no executable action returned"
            break

    return last_fb, executed
