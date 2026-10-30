"""tests/test_defender_rules.py - Defender three-tier mechanism unit tests (local only, no ELK/LLM)

Covers: four signature rule matches, L1 noise injection, L3 threat-intel construction.
Run: cd Zero-APT-Code && python tests/test_defender_rules.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.defender_rules import (
    match_rules, format_rule_matches, inject_noise, build_threat_intel,
    NOISE_TEMPLATES, STANDARD_PORTS,
)

_PASS = 0


def _ok(name):
    global _PASS
    _PASS += 1
    print(f"  PASS {name}")


def _fail(name, msg):
    print(f"  FAIL {name}: {msg}")
    raise SystemExit(1)


def ev(eid, msg):
    return {"@timestamp": "2026-10-28T10:00:00Z", "winlog": {"event_id": str(eid)}, "message": msg}


def test_r1_suspicious_parent_child():
    bad = ev(1, "Process Create:\nRuleName: -\nUtcTime: 2026-10-28 10:00:00\n"
               "Image: C:\\Windows\\System32\\mimikatz.exe\n"
               "ParentImage: C:\\Windows\\System32\\cmd.exe\n")
    hits = match_rules([bad])
    assert len(hits) == 1 and hits[0]["rule"] == "R1_suspicious_parent_child", hits
    # benign: explorer spawns mimikatz? — explorer is not in the suspicious-parent table -> no hit
    benign_parent = ev(1, "Process Create:\nImage: C:\\Tools\\mimikatz.exe\nParentImage: C:\\Windows\\explorer.exe\n")
    assert match_rules([benign_parent]) == []
    # benign: cmd spawns notepad (child not in the attack-tool table) -> no hit
    benign_child = ev(1, "Process Create:\nImage: C:\\Windows\\System32\\notepad.exe\nParentImage: C:\\Windows\\System32\\cmd.exe\n")
    assert match_rules([benign_child]) == []
    _ok("test_r1_suspicious_parent_child")


def test_r2_registry_persistence():
    bad = ev(13, "Registry value set:\nEventType: SetValue\n"
                "TargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil\n")
    hits = match_rules([bad])
    assert len(hits) == 1 and hits[0]["rule"] == "R2_registry_persistence", hits
    benign = ev(13, "Registry value set:\nTargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\n")
    assert match_rules([benign]) == []
    _ok("test_r2_registry_persistence")


def test_r3_executable_in_system_dir():
    bad = ev(11, "File created:\nTargetFilename: C:\\Windows\\Temp\\evil.exe\n")
    assert len(match_rules([bad])) == 1 and match_rules([bad])[0]["rule"] == "R3_executable_in_system_dir"
    benign = ev(11, "File created:\nTargetFilename: C:\\Users\\User1\\Downloads\\report.docx\n")
    assert match_rules([benign]) == []
    _ok("test_r3_executable_in_system_dir")


def test_r4_nonstandard_port():
    bad = ev(3, "Network connection detected:\nDestinationIp: 8.8.8.8\nDestinationPort: 4444\n")
    hits = match_rules([bad])
    assert len(hits) == 1 and hits[0]["rule"] == "R4_nonstandard_port", hits
    for port in (80, 443, 3389, 5985):
        benign = ev(3, f"Network connection detected:\nDestinationPort: {port}\n")
        assert match_rules([benign]) == [], f"standard port {port} must not hit"
    malformed = ev(3, "Network connection detected:\nDestinationPort: abc\n")
    assert match_rules([malformed]) == []
    _ok("test_r4_nonstandard_port")


def test_l1_noise_injection():
    n1 = inject_noise(seed=0)
    n2 = inject_noise(seed=1)
    assert len(n1) == 8, f"expect 8 noise events, got {len(n1)}"
    assert n1 != n2, "different seeds must give different noise"
    # noise is shaped like real winlogbeat events and carries no injection marker
    for e in n1:
        assert "@timestamp" in e and "winlog" in e and "message" in e, e
        assert "noise" not in e["message"].lower(), "noise events must not be self-labeled"
    assert len(NOISE_TEMPLATES) >= 8
    _ok("test_l1_noise_injection")


def test_l3_threat_intel():
    lib = [{"technique_id": "T1003.001"}, {"technique_id": "T1003.001"},
           {"technique_id": "T1059.001"}, {"technique_id": None}]
    text = build_threat_intel(lib)
    assert "T1003.001" in text and "T1059.001" in text
    assert text.count("T1003.001") == 1, "techniques must be deduplicated"
    # accumulated detection history injection
    state = {"round_logs": [{"round": 1, "winner": "blue_win", "blue_evidence_score": 85},
                            {"round": 2, "winner": "red_win", "blue_evidence_score": 40}]}
    text2 = build_threat_intel(lib, state)
    assert "R1: detected=85" in text2, "detection history must be injected at L3"
    _ok("test_l3_threat_intel")


def test_rule_hit_format():
    hits = [{"rule": "R4_nonstandard_port", "eid": "3", "reason": "8.8.8.8:4444", "ts": "2026-10-28T10:00:00Z"}]
    text = format_rule_matches(hits)
    assert "R4_nonstandard_port" in text and "4444" in text
    assert "(no signature rule matched)" == format_rule_matches([])
    _ok("test_rule_hit_format")


if __name__ == "__main__":
    print("== ZERO-APT defender rules tests ==")
    for fn in (test_r1_suspicious_parent_child, test_r2_registry_persistence,
               test_r3_executable_in_system_dir, test_r4_nonstandard_port,
               test_l1_noise_injection, test_l3_threat_intel, test_rule_hit_format):
        fn()
    print(f"== all {_PASS} tests passed ==")
