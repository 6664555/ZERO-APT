"""tests/test_core_mechanisms.py - core-mechanism unit tests (local only, no range/LLM)

Covers: mechanical hard-constraint filtering, hard-condition probe writeback loop, Judge 75-point mechanical adjudication.
Run: cd Zero-APT-Code && python tests/test_core_mechanisms.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.hard_filter import check_action, filter_actions, apply_probe_results
from core.judge_rules import adjudicate, JUDGE_THRESHOLD
from core.loop import init_global_state
from core.archive_env import DEFAULT_ARCHIVE_ENVIRONMENT

_PASS = 0


def _ok(name):
    global _PASS
    _PASS += 1
    print(f"  PASS {name}")


def _fail(name, msg):
    print(f"  FAIL {name}: {msg}")
    raise SystemExit(1)


def make_action(aid, priv="user", deps=None, ports=None):
    return {
        "action_id": aid,
        "display_name": f"test {aid}",
        "preconditions": {
            "required_privilege": priv,
            "dependencies": deps or [],
            "ports_needed": ports or [],
        },
        "postconditions": {},
    }


def test_privilege_mechanical_filter():
    env = {"current_privilege": "user", "available_tools": {}, "open_ports": {}}
    act_admin = make_action("T1", priv="admin")
    act_sys = make_action("T2", priv="system")
    act_user = make_action("T3", priv="user")
    ok, reasons = check_action(act_admin, env)
    assert not ok and reasons, "admin action must be blocked at user privilege"
    feasible, blocked, hct = filter_actions([act_admin, act_sys, act_user], env)
    assert [a["action_id"] for a in feasible] == ["T3"], f"only user action feasible, got {feasible}"
    assert hct == 2, f"hct must count 2 precondition exclusions, got {hct}"
    # after upgrading to admin, admin actions pass and system is still blocked
    env["current_privilege"] = "admin"
    feasible, _, hct = filter_actions([act_admin, act_sys, act_user], env)
    assert [a["action_id"] for a in feasible] == ["T1", "T3"], "after upgrade T1+T3 feasible"
    assert hct == 1
    _ok("test_privilege_mechanical_filter")


def test_dependency_default_true_and_flip():
    env = {"current_privilege": "user", "available_tools": {"mimikatz.exe": True}, "open_ports": {}}
    act = make_action("T4", deps=["mimikatz.exe"])
    assert check_action(act, env)[0], "known tool True -> allowed"
    act_unknown = make_action("T5", deps=["nonexistent_tool_x"])
    assert check_action(act_unknown, env)[0], "unknown dep -> default true (paper: optimistic)"
    # after probing it false it must be mechanically excluded
    apply_probe_results(env, {"tools_unavailable": ["mimikatz.exe"]})
    ok, reasons = check_action(act, env)
    assert not ok and any("mimikatz.exe" in r for r in reasons), "flipped False dep must block"
    _ok("test_dependency_default_true_and_flip")


def test_port_default_true_and_flip():
    env = {"current_privilege": "user", "available_tools": {}, "open_ports": {}}
    act135 = make_action("T6", ports=["135"])
    assert check_action(act135, env)[0], "unprobed port -> default true"
    apply_probe_results(env, {"ports_unreachable": ["135"]})
    ok, reasons = check_action(act135, env)
    assert not ok and "port_unreachable" in reasons, "probed-unreachable port must block"
    _ok("test_port_default_true_and_flip")


def test_forbidden_and_hct():
    env = {"current_privilege": "user", "available_tools": {}, "open_ports": {}}
    acts = [make_action("T7"), make_action("T8")]
    feasible, blocked, hct = filter_actions(acts, env, forbidden=["T8"])
    assert [a["action_id"] for a in feasible] == ["T7"]
    assert blocked["T8"] == ["forbidden_by_judge"], f"forbidden reason expected, got {blocked}"
    assert hct == 0, "forbidden exclusion is not a hard-constraint trigger"
    _ok("test_forbidden_and_hct")


def test_probe_writeback_loop_closure():
    """Paper's three-step loop: default true -> probe flips false -> next round's Dispatcher excludes."""
    env = {"current_privilege": "user",
           "available_tools": {"PsExec.exe": True},
           "open_ports": {}}
    acts = [make_action("T9", priv="admin", deps=["PsExec.exe"]),
            make_action("T10", priv="user", deps=["PsExec.exe"])]
    assert len(filter_actions(acts, env)[0]) == 1, "only T10 feasible at user"
    # Executor probe: privilege confirmed admin + PsExec missing
    changed = apply_probe_results(env, {"privilege": "admin", "tools_unavailable": ["PsExec.exe"]})
    assert ("current_privilege", "admin") in changed and ("available_tools.PsExec.exe", False) in changed, changed
    # raise-only / repeated probe does not recount
    assert apply_probe_results(env, {"privilege": "user"}) == []
    assert apply_probe_results(env, {"tools_unavailable": ["PsExec.exe"]}) == []
    # next round: T9 still excluded because PsExec is missing (privilege satisfied but tool unavailable)
    feasible, blocked, hct = filter_actions(acts, env)
    assert [a["action_id"] for a in feasible] == [], f"PsExec missing blocks both, got {feasible}"
    assert hct == 2 and blocked["T9"] == ["dependency:PsExec.exe=False"]
    _ok("test_probe_writeback_loop_closure")


def test_judge_threshold_mechanics():
    assert adjudicate(75) == "blue_win", ">=75 must be blue_win (boundary)"
    assert adjudicate(74) == "red_win", "<75 must be red_win (boundary)"
    assert adjudicate(0) == "red_win"
    assert adjudicate(100) == "blue_win"
    assert adjudicate(None) == "red_win", "missing score -> no valid evidence -> red_win"
    assert adjudicate("high") == "red_win"
    assert JUDGE_THRESHOLD == 75
    _ok("test_judge_threshold_mechanics")


def test_illegal_enum_tolerance():
    """Rat_lib.jsonl:757's illegal enum value 'administrator' must be tolerated by the mechanical matcher."""
    env = {"current_privilege": "admin", "available_tools": {}, "open_ports": {}}
    act = make_action("T11", priv="administrator")
    assert check_action(act, env)[0], "'administrator' must rank equal to 'admin'"
    _ok("test_illegal_enum_tolerance")


def test_cross_experiment_state_isolation():
    """Nested environment state must not leak across experiments (blind-review C2: shallow-copy leak fix verification)."""
    s1 = init_global_state("m1", 5)
    s2 = init_global_state("m2", 5)
    apply_probe_results(s1["archive_environment"], {"tools_unavailable": ["mimikatz.exe"],
                                                    "ports_unreachable": ["135"]})
    s1["archive_environment"]["discovered_info"]["x"] = 1
    env2 = s2["archive_environment"]
    assert env2["available_tools"]["mimikatz.exe"] is True, "s1 mutation leaked into s2 tools"
    assert env2["open_ports"].get("135") is None, "s1 mutation leaked into s2 ports"
    assert "x" not in env2["discovered_info"], "s1 discovery leaked into s2"
    assert DEFAULT_ARCHIVE_ENVIRONMENT["available_tools"]["mimikatz.exe"] is True, "module default mutated"
    _ok("test_cross_experiment_state_isolation")


def test_judge_state_accumulation():
    """Judge discoveries accumulate (blind-review C2: empty update must not overwrite history; None must not crash)."""
    from agents.purple import _apply_judge_result
    state = init_global_state("m", 5)
    disc = state["archive_environment"]["discovered_info"]
    disc["files_found"] = ["C:\\old.txt"]
    disc["credentials"] = [{"username": "UserX", "password": "p1"}]
    ti = {"admin_name": "Administrator", "admin_password": ""}
    # None / empty environment_update: no crash, no overwrite
    _apply_judge_result(state, {"winner": "red_win", "environment_update": None}, ti)
    _apply_judge_result(state, {"winner": "red_win", "environment_update": {}}, ti)
    assert disc["files_found"] == ["C:\\old.txt"], "empty update must not wipe history"
    assert disc["credentials"] == [{"username": "UserX", "password": "p1"}]
    # new discoveries accumulate (not overwrite), same username deduped
    _apply_judge_result(state, {"winner": "red_win", "environment_update": {
        "files_found": ["C:\\new.txt"],
        "credentials": [{"username": "UserX", "password": "p1"}],
        "other": {"priv": "x"}}}, ti)
    assert disc["files_found"] == ["C:\\old.txt", "C:\\new.txt"]
    assert len(disc["credentials"]) == 1, "duplicate username must be deduped"
    assert disc["other"] == {"priv": "x"}
    # Administrator credentials -> privilege escalation
    _apply_judge_result(state, {"winner": "red_win", "environment_update": {
        "credentials": [{"username": "Administrator", "password": "P@ss"}]}}, ti)
    assert ti["admin_password"] == "P@ss"
    assert state["archive_environment"]["current_privilege"] == "admin"
    _ok("test_judge_state_accumulation")


def test_experiment_id_unique():
    """Experiment IDs are unique to the microsecond (blind-review C1: same-second batch runs must not share a directory)."""
    from core.loop import generate_experiment_id
    ids = {generate_experiment_id() for _ in range(50)}
    assert len(ids) == 50, "experiment IDs must not collide"
    _ok("test_experiment_id_unique")


def test_env_overrides_probe_style():
    """Scenario initial conditions (S5 pre-block) flip hard conditions via the probe writeback mechanism."""
    s = init_global_state("m", 5, env_overrides={"tools_unavailable": ["PsExec.exe"],
                                                 "ports_unreachable": ["135"]})
    env = s["archive_environment"]
    assert env["available_tools"]["PsExec.exe"] is False, "S5 pre-block must flip the tool false"
    assert env["open_ports"]["135"] is False, "S5 pre-block must flip the port false"
    _ok("test_env_overrides_probe_style")


if __name__ == "__main__":
    print(f"== ZERO-APT core mechanism tests (judge threshold = {JUDGE_THRESHOLD}) ==")
    for fn in (test_privilege_mechanical_filter,
               test_dependency_default_true_and_flip,
               test_port_default_true_and_flip,
               test_forbidden_and_hct,
               test_probe_writeback_loop_closure,
               test_judge_threshold_mechanics,
               test_illegal_enum_tolerance,
               test_cross_experiment_state_isolation,
               test_judge_state_accumulation,
               test_experiment_id_unique,
               test_env_overrides_probe_style):
        fn()
    print(f"== all {_PASS} tests passed ==")
