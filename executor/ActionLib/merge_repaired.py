"""executor/ActionLib/merge_repaired.py - action-library repair/merge script

Merge the structurally-complete Windows actions from repaired_actions.jsonl into the runtime
library, producing Rat_lib_v2.jsonl. Rat_lib.jsonl (original runtime library) and
repaired_actions.jsonl (repaired library) are both kept read-only and unchanged.

Merge strategy (each step lists details in the report):
1. keep only rows with platform == windows (drop linux/macos rows; the paper's library is Windows-only)
2. drop rows missing core schema: no command_template (non-executable, including executor='manual' human-interaction actions),
   no preconditions (cannot be mechanically filtered), no platform/executor, pre/postconditions not objects (corrupted type)
3. normalize: non-canonical required_privilege "administrator" -> "admin"; missing postconditions filled with {}
4. deduplicate by action_id: Rat_lib.jsonl is the runtime baseline; on conflict Rat_lib wins
5. validate every output row against the runtime schema (action_id/platform/executor/command_template/preconditions/postconditions)

Run: cd Zero-APT-Code && python executor/ActionLib/merge_repaired.py
"""

import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_LIB = os.path.join(SCRIPT_DIR, "Rat_lib.jsonl")
REPAIRED_LIB = os.path.join(SCRIPT_DIR, "repaired_actions.jsonl")
OUT_LIB = os.path.join(SCRIPT_DIR, "Rat_lib_v2.jsonl")

REQUIRED_FIELDS = ("action_id", "platform", "executor", "command_template", "preconditions", "postconditions")


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def normalize(row):
    """Normalize one action: privilege enum, postconditions fallback. Returns (row, list of fixes)."""
    fixes = []
    pre = row.setdefault("preconditions", {})
    priv = pre.get("required_privilege")
    if priv is not None and str(priv).strip().lower() not in ("user", "admin", "system"):
        fixes.append(f"required_privilege '{priv}' -> 'admin'")
        pre["required_privilege"] = "admin"
    if not isinstance(pre.get("dependencies"), list):
        pre["dependencies"] = list(pre.get("dependencies") or [])
    if not isinstance(pre.get("ports_needed"), list):
        pre["ports_needed"] = list(pre.get("ports_needed") or [])
    if not row.get("postconditions"):
        row["postconditions"] = {}
        fixes.append("postconditions {} filled")
    return row, fixes


def main():
    base = load(BASE_LIB)
    repaired = load(REPAIRED_LIB)
    report = {"base_loaded": len(base), "repaired_loaded": len(repaired)}
    dropped, fixes_log = [], []

    merged_by_id = {}
    for row in base:  # Rat_lib is the baseline, wins on conflict; bad baseline rows are also dropped and logged
        reasons = []
        for field in REQUIRED_FIELDS:
            if not row.get(field):
                reasons.append(f"missing/empty {field}")
        if not isinstance(row.get("preconditions"), dict):
            reasons.append("preconditions not a dict")
        if not isinstance(row.get("postconditions"), dict):
            reasons.append("postconditions not a dict")
        if reasons:
            dropped.append({"action_id": row.get("action_id", "?"), "reasons": reasons,
                            "source": "Rat_lib base"})
            continue
        # baseline rows are normalized too (e.g. illegal privilege enum administrator -> admin)
        norm_row, fixes = normalize(dict(row))
        if fixes:
            fixes_log.append({"action_id": row["action_id"], "fixes": fixes,
                              "source": "Rat_lib base"})
        merged_by_id[row["action_id"]] = norm_row
    added_ids = []
    for row in repaired:
        aid = row.get("action_id", "")
        reasons = []
        if row.get("platform") != "windows":
            reasons.append(f"platform={row.get('platform')}")
        for field in REQUIRED_FIELDS:
            if not row.get(field):
                reasons.append(f"missing/empty {field}")
        if not isinstance(row.get("preconditions"), dict):
            reasons.append("preconditions not a dict")
        if not isinstance(row.get("postconditions"), dict):
            reasons.append("postconditions not a dict")
        if reasons:
            dropped.append({"action_id": aid, "reasons": reasons})
            continue
        norm_row, fixes = normalize(dict(row))
        if fixes:
            fixes_log.append({"action_id": aid, "fixes": fixes})
        if aid in merged_by_id:
            report.setdefault("dup_skipped", []).append(aid)  # already in baseline, skip
            continue
        merged_by_id[aid] = norm_row
        added_ids.append(aid)

    merged = list(merged_by_id.values())
    # full validation before writing (including type checks)
    invalid = []
    for r in merged:
        if any(not r.get(f) for f in REQUIRED_FIELDS):
            invalid.append((r.get("action_id", "?"), "empty field"))
        elif not isinstance(r.get("preconditions"), dict) or not isinstance(r.get("postconditions"), dict):
            invalid.append((r.get("action_id", "?"), "pre/postconditions not dict"))
    if invalid:
        print(f"ABORT: {len(invalid)} rows failed schema validation: {invalid[:5]}")
        return 1

    with open(OUT_LIB, "w", encoding="utf-8") as f:
        for row in merged:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    report.update({
        "added": len(added_ids),
        "dropped": len(dropped),
        "merged_total": len(merged),
        "invalid_after_merge": len(invalid),
    })
    print("== action library merge report ==")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"dropped rows: {json.dumps(dropped, ensure_ascii=False)}")
    print(f"normalized rows: {json.dumps(fixes_log, ensure_ascii=False)}")
    print(f"added action_ids: {json.dumps(added_ids, ensure_ascii=False)}")
    print(f"output: {OUT_LIB}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
