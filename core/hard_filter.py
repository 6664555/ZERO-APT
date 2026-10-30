"""core/hard_filter.py - mechanical hard-constraint filtering + hard-condition probe writeback.

Code-level implementation of the paper's third mechanism (§3.3, hard-constraint-filtered
action library):
- An action's preconditions (required_privilege / dependencies / ports_needed) are matched
  against the environment state archive_environment via structured table lookup, with no LLM call.
- Hard conditions default to satisfied (unprobed = allow, the paper's "default to true"); after
  the Executor probes one as unmet, it is flipped to False and the next round's Dispatcher
  mechanically excludes actions that depend on it.
- HCT (Hard Constraint Triggers) counting feeds the metric.
"""

from typing import Any, Dict, List, Tuple

# Privilege rank: user < admin < system (including non-canonical spellings in the action library)
PRIVILEGE_RANK = {"user": 0, "admin": 1, "administrator": 1, "system": 2}

# Reserved keys in Executor discoveries used for hard-condition writeback (other keys are soft)
PROBE_KEYS = ("privilege", "tools_unavailable", "tools_available", "ports_unreachable")

# Dependency lookup order: tool / module / environment flag / runtime
_DEP_TABLES = ("available_tools", "available_modules", "environment_flags", "runtimes")


def _norm_priv(priv: Any) -> str:
    return str(priv or "user").strip().lower()


def _privilege_satisfied(required: str, current: str) -> bool:
    req = PRIVILEGE_RANK.get(_norm_priv(required))
    cur = PRIVILEGE_RANK.get(_norm_priv(current))
    if req is None or cur is None:
        return True  # unknown requirement/state: optimistic allow (default true)
    return cur >= req


def _dependency_satisfied(dep: str, env: Dict[str, Any]) -> bool:
    """Dependency lookup: an explicit False in any environment table is unsatisfied;
    absent or True -> default satisfied."""
    for table in _DEP_TABLES:
        table_map = env.get(table) or {}
        if dep in table_map:
            return bool(table_map[dep])
    return True  # absent -> unknown -> default true


def _ports_satisfied(ports: List[Any], env: Dict[str, Any]) -> bool:
    open_ports = env.get("open_ports") or {}
    for p in ports or []:
        key = str(p)
        if key in open_ports and not open_ports[key]:
            return False  # explicitly probed unreachable
        # unprobed -> default reachable
    return True


def check_action(action: Dict[str, Any], env: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Mechanically check one action's hard conditions. Returns (satisfied, reason list)."""
    pre = action.get("preconditions") or {}
    reasons = []
    required_priv = pre.get("required_privilege")
    if required_priv and not _privilege_satisfied(
        required_priv, env.get("current_privilege", "user")
    ):
        reasons.append(f"privilege:{required_priv}>{env.get('current_privilege')}")
    for dep in pre.get("dependencies") or []:
        if not _dependency_satisfied(dep, env):
            reasons.append(f"dependency:{dep}=False")
    if not _ports_satisfied(pre.get("ports_needed") or [], env):
        reasons.append("port_unreachable")
    return (not reasons, reasons)


def filter_actions(actions, env: Dict[str, Any], forbidden=None):
    """Mechanical filter before Dispatcher Phase 1 (paper: Dispatcher table lookup, not LLM judgment).

    Returns (feasible, blocked_reasons, hct):
    - feasible: actions satisfying hard conditions and not on the Judge forbidden list
    - blocked_reasons: {action_id: [reasons]}, covering hard conditions and forbidden
    - hct: candidate count mechanically excluded for precondition mismatch (HCT metric)
    """
    forbidden = set(forbidden or [])
    feasible, blocked_reasons, hct = [], {}, 0
    for act in actions:
        aid = act.get("action_id", "")
        reasons = []
        if aid in forbidden:
            reasons.append("forbidden_by_judge")
        ok, hard_reasons = check_action(act, env)
        if not ok:
            reasons.extend(hard_reasons)
            hct += 1
        if reasons:
            blocked_reasons[aid] = reasons
        else:
            feasible.append(act)
    return feasible, blocked_reasons, hct


def apply_probe_results(env: Dict[str, Any], probes: Dict[str, Any]) -> List[Tuple[str, Any]]:
    """Write Executor probe results back into environment hard conditions (step 2 of the
    paper's three-step loop: probe -> flip).

    Only the reserved keys (PROBE_KEYS) are read; the rest are ignored (handled as soft
    conditions by the caller):
    - "privilege": "admin"|"system" -> raise current_privilege (raise-only)
    - "tools_unavailable": [names...] -> set the corresponding table entries False
    - "tools_available": [names...] -> explicitly confirm True
    - "ports_unreachable": [ports...] -> set open_ports False
    Returns the list of changes [(field, new_value), ...].
    """
    changed: List[Tuple[str, Any]] = []

    priv = _norm_priv(probes.get("privilege", ""))
    if priv:
        cur_rank = PRIVILEGE_RANK.get(_norm_priv(env.get("current_privilege", "user")), -1)
        new_rank = PRIVILEGE_RANK.get(priv, -1)
        if new_rank > cur_rank:
            env["current_privilege"] = priv
            changed.append(("current_privilege", priv))

    for name in probes.get("tools_unavailable") or []:
        key = str(name)
        if env.setdefault("available_tools", {}).get(key) is not False:
            env["available_tools"][key] = False
            changed.append((f"available_tools.{key}", False))
    for name in probes.get("tools_available") or []:
        key = str(name)
        env.setdefault("available_tools", {})[key] = True

    for p in probes.get("ports_unreachable") or []:
        key = str(p)
        if env.setdefault("open_ports", {}).get(key) is not False:
            env["open_ports"][key] = False
            changed.append((f"open_ports.{key}", False))

    return changed
