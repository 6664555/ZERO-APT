"""tests/test_stix_export.py - STIX 2.1 CTI export tests (needs stix2; auto-skips when absent).

Covers: bundle object types complete, technique dedup + causal-chain relationship,
per-EID SCO mapping, technique fallback without action_lib.
Run: cd Zero-APT-Code && python tests/test_stix_export.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness.stix_export import build_stix_bundle

_PASS = 0


def _ok(name):
    global _PASS
    _PASS += 1
    print(f"  PASS {name}")


def _fail(name, msg):
    print(f"  FAIL {name}: {msg}")
    raise SystemExit(1)


def _state():
    return {
        "experiment_id": "exp_test_stix",
        "mission": "Extract local credentials",
        "goal_achieved": True,
        "loop_count": 2,
        "used_action_ids": ["T1001.002-001", "T1053.005-002", "T1001.002-001"],
        "round_logs": [
            {
                "round": 1,
                "winner": "red_win",
                "red_commands": [
                    {"action": "run_command", "command": "whoami /groups", "status": "success"},
                    {"action": "finalize", "command": "", "status": "finalized"},
                ],
                "blue_rule_matches": [
                    {"rule": "R1_suspicious_parent_child", "eid": "1", "reason": "cmd.exe -> mimikatz.exe"},
                    {"rule": "R4_nonstandard_port", "eid": "3", "reason": "1.2.3.4:4444"},
                ],
            },
        ],
    }


def _action_lib():
    return [
        {"action_id": "T1001.002-001", "technique_id": "T1001.002",
         "display_name": "stego exfil"},
        {"action_id": "T1053.005-002", "technique_id": "T1053.005",
         "display_name": "scheduled task persistence"},
    ]


def test_bundle_object_types():
    bundle = build_stix_bundle(_state(), action_lib=_action_lib())
    data = json.loads(bundle.serialize(pretty=True))
    types = {o["type"] for o in data["objects"]}
    for required in ("identity", "marking-definition", "intrusion-set",
                     "attack-pattern", "observed-data", "report"):
        assert required in types, f"missing object type {required}"
    assert data["type"] == "bundle"
    _ok("test_bundle_object_types")


def test_technique_dedup_and_causal_chain():
    bundle = build_stix_bundle(_state(), action_lib=_action_lib())
    data = json.loads(bundle.serialize(pretty=True))
    aps = [o for o in data["objects"] if o["type"] == "attack-pattern"]
    rels = [o for o in data["objects"] if o["type"] == "relationship"]
    assert len(aps) == 2, f"expect 2 deduped techniques, got {len(aps)}"
    assert len(rels) == 1, f"expect 1 causal relationship (n-1), got {len(rels)}"
    ext = {r["external_id"] for a in aps for r in a["external_references"]
           if r.get("source_name") == "mitre-attack"}
    assert ext == {"T1001.002", "T1053.005"}, f"wrong mitre refs {ext}"
    _ok("test_technique_dedup_and_causal_chain")


def test_rule_match_sco_mapping():
    state = _state()
    state["round_logs"][0]["blue_rule_matches"] = [
        {"rule": "R1", "eid": "1", "reason": "cmd.exe -> mimikatz.exe"},
        {"rule": "R2", "eid": "13", "reason": "HKLM\\...\\Run"},
        {"rule": "R3", "eid": "11", "reason": "C:\\Windows\\System32\\x.dll"},
        {"rule": "R4", "eid": "3", "reason": "1.2.3.4:4444"},
    ]
    bundle = build_stix_bundle(state, action_lib=_action_lib())
    data = json.loads(bundle.serialize(pretty=True))
    obs = [o for o in data["objects"] if o["type"] == "observed-data"]
    sco_types = [sorted(v["type"] for v in o["objects"].values()) for o in obs]
    assert ["process"] in sco_types, f"EID1 -> process, got {sco_types}"
    assert ["windows-registry-key"] in sco_types, f"EID13 -> registry, got {sco_types}"
    assert ["file"] in sco_types, f"EID11 -> file, got {sco_types}"
    assert ["ipv4-addr", "network-traffic"] in sco_types, f"EID3 -> network, got {sco_types}"
    _ok("test_rule_match_sco_mapping")


def test_no_action_lib_fallback():
    """Without action_lib, derive the technique from the action_id; must not crash and still dedup."""
    bundle = build_stix_bundle(_state())
    data = json.loads(bundle.serialize(pretty=True))
    aps = [o for o in data["objects"] if o["type"] == "attack-pattern"]
    assert len(aps) == 2, f"fallback should still dedup to 2, got {len(aps)}"
    _ok("test_no_action_lib_fallback")


if __name__ == "__main__":
    try:
        import stix2  # noqa: F401
    except ImportError:
        print("SKIP stix_export tests: stix2 not installed (pip install stix2)")
        sys.exit(0)
    print("== ZERO-APT STIX export tests ==")
    for fn in (test_bundle_object_types, test_technique_dedup_and_causal_chain,
               test_rule_match_sco_mapping, test_no_action_lib_fallback):
        fn()
    print(f"== all {_PASS} tests passed ==")
