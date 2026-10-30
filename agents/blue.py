"""
blue.py - Defender module (paper §3.2, three intensity tiers L1/L2/L3)
Fetch Sysmon logs from ELK -> (L2/L3: four signature rule matches) -> (L1: noise injection)
-> (L3: threat-intel injection) -> Monitor LLM analysis -> return the detection result.
"""

import json
from utils.monitor_tools import format_logs
from agents.prompts.monitor import BLUE_TEAM_MONITOR_PROMPT
from utils.llm import connect_llm_json
from core.defender_rules import match_rules, format_rule_matches, inject_noise, build_threat_intel
from core.interfaces import LogSource, DefaultLogSource


TIER_DESCRIPTIONS = {
    "L1": "L1 (Low): noisy logs, NO signature rules, NO threat intelligence. Pure LLM anomaly judgment against background noise.",
    "L2": "L2 (Medium): clean logs, four Sysmon signature rules (EID 1/3/11/12-14) as evidence anchors, LLM contextual reasoning and false-positive suppression. No threat intelligence.",
    "L3": "L3 (High): L2 rules PLUS known-adversary threat intelligence (attacker TTP list and accumulated detection history).",
}


def blue_team(state, action_lib=None, defender_tier="L2", api_key=None, LLM_type='deepseek', log_source=None):
    """
    Args:
        state: GlobalState, containing blue_input_logs/blue_feedback etc.
        action_lib: action library (used for L3 threat-intel injection)
        defender_tier: 'L1' | 'L2' | 'L3' (paper Table: defender_tiers)
        api_key: LLM API key
        LLM_type: 'deepseek' | 'claude' | 'mock'
        log_source: LogSource adapter (default DefaultLogSource -> ELK winlogbeat-*)

    Returns:
        dict: {has_intrusion, detected_techniques, confidence(0-100), evidence, attack_intent, analysis}
    """
    log_source = log_source or DefaultLogSource()
    tier = (defender_tier or "L2").upper()
    if tier not in TIER_DESCRIPTIONS:
        print(f"  [Blue] unknown tier '{tier}', fallback to L2")
        tier = "L2"

    # 1. Fetch the last 1 minute of logs from the log source (ELK winlogbeat-* or the dry-run fake source)
    raw_logs = log_source.get_logs(minutes=1)

    # 2. (L2/L3) four signature rule matches, hits used as anchor evidence; L1 skips
    rule_hits = match_rules(raw_logs) if tier in ("L2", "L3") else []
    state["blue_rule_matches"] = [{"rule": h["rule"], "eid": h["eid"], "reason": h["reason"]} for h in rule_hits]

    # 3. L1: mix noise with real events before formatting (ensures noise reaches the Monitor,
    #    not truncated); non-L1: format the first 20 events directly
    if tier == "L1":
        raw_logs = list(raw_logs)[:12] + inject_noise(seed=state.get("loop_count", 0))
        logs_text = format_logs(raw_logs, max_events=20)
    else:
        logs_text = format_logs(raw_logs, max_events=20)

    # 4. Save raw logs for audit
    state["blue_input_logs"] = logs_text

    # 5. Fill the prompt template (tier description / rule hits / threat intel).
    #    The placeholder tokens below mirror the Chinese tokens in agents/prompts/monitor.py;
    #    they are kept verbatim to preserve the prompt template.
    prompt = BLUE_TEAM_MONITOR_PROMPT.replace("{日志文本}", logs_text)
    prompt = prompt.replace("{防御档位}", TIER_DESCRIPTIONS[tier])
    prompt = prompt.replace("{规则命中}", format_rule_matches(rule_hits) if tier in ("L2", "L3") else "(L1: no signature rules applied)")
    prompt = prompt.replace("{威胁情报}", build_threat_intel(action_lib, state) if tier == "L3" else "(no threat intelligence injected)")

    # 6. Call the LLM and parse JSON
    result = connect_llm_json(prompt, api_key, LLM_type)

    # 7. Serialize into state
    state["blue_feedback"] = json.dumps(result, ensure_ascii=False)

    # 8. Return the detection result
    return result
