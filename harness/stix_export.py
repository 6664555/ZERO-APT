"""harness/stix_export.py - export one experiment's full audit data as a STIX 2.1 bundle.

Requires the stix2 library (pip install stix2); it is only invoked when CTI_FORMAT=stix|both —
the default markdown output neither imports this module nor depends on stix2.

Object mapping (paper §3.4 auditability / "STIX 2.0 alignment"):
- identity        : ZERO-APT platform identity
- intrusion-set   : one experiment = one intrusion activity
- attack-pattern  : each MITRE technique used (external_references point at ATT&CK)
- relationship    : causal chain between techniques
- observed-data   : each executed command (Process SCO) and each signature rule hit (SCO by EID)
- report          : wraps all of the above + experiment metadata
"""

import re
from datetime import datetime, timezone

_TECH_RE = re.compile(r"^T\d+(?:\.\d+)?")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _technique_of(action_id):
    m = _TECH_RE.match(str(action_id or ""))
    return m.group(0) if m else str(action_id)


def build_stix_bundle(state, action_lib=None):
    import stix2  # lazy import: the default markdown output does not need stix2

    # action_id -> action dict (for technique_id / technique_name lookup)
    lib = {}
    for act in (action_lib or []):
        if isinstance(act, dict) and act.get("action_id"):
            lib[act["action_id"]] = act

    # TLP:AMBER marking (library-provided object with a fixed id that passes stix2 validation) + platform identity
    tlp = stix2.TLP_AMBER
    identity = stix2.Identity(
        name="ZERO-APT", identity_class="system",
        description="ZERO-APT automated penetration-testing framework",
        object_marking_refs=[tlp.id])

    objs = [identity, tlp]

    # 1) intrusion activity = one experiment
    intr = stix2.IntrusionSet(
        name=f"ZERO-APT experiment {state.get('experiment_id', '')}",
        description=state.get("mission", ""),
        created_by_ref=identity.id, object_marking_refs=[tlp.id])
    objs.append(intr)

    # 2) attack-pattern: deduplicated, ordered by first appearance
    ap_by_tech = {}
    tech_order = []
    for aid in state.get("used_action_ids", []):
        tid = lib.get(aid, {}).get("technique_id") or _technique_of(aid)
        if tid and tid not in ap_by_tech:
            ap = stix2.AttackPattern(
                name=lib.get(aid, {}).get("technique_name") or tid,
                external_references=[{"source_name": "mitre-attack", "external_id": tid}],
                created_by_ref=identity.id, object_marking_refs=[tlp.id])
            ap_by_tech[tid] = ap
            tech_order.append(tid)
            objs.append(ap)

    # 3) causal-chain relationship: technique_i -> technique_{i+1}
    for i in range(len(tech_order) - 1):
        objs.append(stix2.Relationship(
            source_ref=ap_by_tech[tech_order[i]].id,
            relationship_type="uses",
            target_ref=ap_by_tech[tech_order[i + 1]].id,
            created_by_ref=identity.id, object_marking_refs=[tlp.id]))

    # 4) observed-data: executed commands + rule hits
    for rl in state.get("round_logs", []):
        for c in (rl.get("red_commands") or []):
            if c.get("action") == "run_command" and c.get("command"):
                objs.append(stix2.ObservedData(
                    first_observed=_now(), last_observed=_now(), number_observed=1,
                    objects={"0": stix2.Process(command_line=c["command"])},
                    created_by_ref=identity.id, object_marking_refs=[tlp.id]))
        for hit in (rl.get("blue_rule_matches") or []):
            objs.append(stix2.ObservedData(
                first_observed=_now(), last_observed=_now(), number_observed=1,
                objects=_objects_for_rule(stix2, hit),
                created_by_ref=identity.id, object_marking_refs=[tlp.id]))

    # 5) report wrapping all objects
    winners = [rl.get("winner") for rl in state.get("round_logs", [])]
    report = stix2.Report(
        name=f"ZERO-APT CTI Report — {state.get('experiment_id', '')}",
        published=_now(),
        description=(
            f"mission={state.get('mission')} "
            f"goal_achieved={state.get('goal_achieved')} "
            f"rounds={state.get('loop_count')} winner_history={winners}"),
        object_refs=[o.id for o in objs if o.id not in (identity.id, tlp.id)],
        created_by_ref=identity.id, object_marking_refs=[tlp.id])
    objs.append(report)

    return stix2.Bundle(objects=objs)


def _objects_for_rule(stix2, hit):
    """Pick the most appropriate SCO by signature-rule EID; fall back to Process on parse failure. Returns {key: SCO} for ObservedData."""
    eid = str(hit.get("eid", ""))
    reason = str(hit.get("reason", ""))
    if eid == "3":
        # reason is "dest_ip:port"; NetworkTraffic requires dst_ref pointing at an address object
        dest_ip, _, port = reason.rpartition(":")
        try:
            ip = stix2.IPv4Address(value=dest_ip.strip())
            nt = stix2.NetworkTraffic(dst_ref=ip.id, dst_port=int(port), protocols=["tcp"])
            return {"0": nt, "1": ip}
        except (TypeError, ValueError):
            pass
    if eid in ("12", "13", "14"):
        return {"0": stix2.WindowsRegistryKey(key=reason)}
    if eid == "11":
        return {"0": stix2.File(name=reason)}
    # EID 1: reason is "parent -> child" (STIX 2.1 Process has no `name` property, so use command_line)
    child = reason.split("->")[-1].strip() if "->" in reason else reason
    return {"0": stix2.Process(command_line=child)}
