"""
scan_action.py - scan and extract attack actions
Loads actions from the action library Rat_lib.jsonl, and filters/classifies them by
preconditions, postconditions, tags, etc.
"""

import json
import os
import re
from functools import lru_cache


@lru_cache(maxsize=1)
def _load_actions():
    """Load the action library and return all action tuples (cached to avoid repeated I/O).

    Prefers Rat_lib_v2.jsonl (the repaired/merged library produced by merge_repaired.py: the
    Windows actions plus repaired_actions, with schema-incomplete / non-executable rows removed);
    falls back to the original Rat_lib.jsonl when v2 is absent.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    lib_v2 = os.path.join(script_dir, "ActionLib", "Rat_lib_v2.jsonl")
    lib_v1 = os.path.join(script_dir, "ActionLib", "Rat_lib.jsonl")
    lib_path = lib_v2 if os.path.exists(lib_v2) else lib_v1
    actions = []
    with open(lib_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                actions.append(json.loads(line))
    return tuple(actions)


def _build_id_index():
    """Build an O(1) action_id -> action index"""
    return {act["action_id"]: act for act in _load_actions()}


def scan_actions(action_id=None, tags=None):
    """Find actions by action_id and/or tags; id lookup is O(1), tags are a linear scan"""
    # action_id exact match — O(1) index lookup
    if action_id is not None:
        idx = _build_id_index()
        act = idx.get(action_id)
        if act is None:
            return []
        # if tags filtering is also requested, verify against the linear scan (consistency)
        if tags is not None:
            return _filter_by_tags([act], tags)
        return [act]

    # tags-only filter — linear scan
    actions = _load_actions()
    if tags is not None:
        return _filter_by_tags(actions, tags)
    return list(actions)


def _filter_by_tags(actions, tags):
    """Filter actions by tags; accepts a comma-separated string or a list"""
    if isinstance(tags, str):
        tag_list = [t.strip().lower() for t in tags.split(",") if t.strip()]
    else:
        tag_list = [t.lower() for t in tags]
    result = []
    for act in actions:
        act_tags = [t.lower() for t in act.get("tags", [])]
        if any(t in act_tags for t in tag_list):
            result.append(act)
    return result


def build_index(action_lib=None):
    """Build an O(1) action_id -> action index (public alias)"""
    return _build_id_index()


def get_source_actions(action: dict):
    """Extract action_id references from an action's description/params/command template, O(1) index lookup for related actions."""
    id_pattern = re.compile(r"T\d+(?:\.\d+)?(?:-\d+)?")

    # collect all text fields
    texts = []
    if action.get("description"):
        texts.append(action["description"])
    if action.get("command_template"):
        texts.append(action["command_template"])
    for param in action.get("parameters", {}).values():
        if param.get("description"):
            texts.append(param["description"])

    # extract all matching IDs
    matched_ids = set()
    for text in texts:
        for m in id_pattern.finditer(text):
            matched_ids.add(m.group())

    if not matched_ids:
        return []

    # O(1) index lookup, reusing the cached action library
    idx = _build_id_index()
    result = []
    for aid in matched_ids:
        act = idx.get(aid)
        if act:
            result.append(act)

    return result


def main():
    """Test interface for the two functions above: manually input an action_id, print both lookups."""
    aid = input("Enter an action_id (e.g. T1001.002-001): ").strip()
    if not aid:
        print("No action_id entered")
        return

    print(f"\n=== scan_actions lookup: {aid} ===")
    matched = scan_actions(action_id=aid)
    if not matched:
        print("Action not found")
        return

    act = matched[0]
    print(f"Found: {act['action_id']} — {act['display_name']}")

    print(f"\n=== get_source_actions related actions ===")
    related = get_source_actions(act)
    if not related:
        print("No related actions found")
    else:
        for r in related:
            print(f"  {r['action_id']} — {r['display_name']}")


if __name__ == "__main__":
    main()
