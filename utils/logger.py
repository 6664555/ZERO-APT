"""
logger.py - outputs management utility
Experiment data (chain-of-thought, CTI reports, full round logs) persisted to the
outputs directory (override with OUTPUT_DIR env var), organized by experiment ID.
"""

import os
import json

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "outputs")


def _exp_dir(experiment_id):
    return f"{OUTPUT_DIR}/{experiment_id}"


def save_cots(round_data, experiment_id, round_num):
    """Save Attacker-Defender-Judge explicit chain of thought to {OUTPUT_DIR}/{experiment_id}/CoTs/round_{round_num}.jsonl"""
    dir_path = f"{_exp_dir(experiment_id)}/CoTs"
    os.makedirs(dir_path, exist_ok=True)
    path = f"{dir_path}/round_{round_num}.jsonl"
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(round_data, ensure_ascii=False) + "\n")
    return path


def save_report(report_text, experiment_id):
    """Save CTI report to {OUTPUT_DIR}/{experiment_id}/CTI_report.md"""
    dir_path = _exp_dir(experiment_id)
    os.makedirs(dir_path, exist_ok=True)
    path = f"{dir_path}/CTI_report.md"
    text = report_text if isinstance(report_text, str) else "(LLM did not generate a report, please check the API connection)"
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def save_stix_bundle(bundle, experiment_id):
    """Save STIX 2.1 bundle to {OUTPUT_DIR}/{experiment_id}/CTI_report.stix.json"""
    dir_path = _exp_dir(experiment_id)
    os.makedirs(dir_path, exist_ok=True)
    path = f"{dir_path}/CTI_report.stix.json"
    with open(path, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))
    return path


def save_round_logs(state, experiment_id):
    """Save complete round_logs (full audit data: commands, planner/judge reasoning,
    backtrack events, HCT, rule matches) to {OUTPUT_DIR}/{experiment_id}/round_logs.json.
    Data source for CCS human review and post-hoc metric re-checking."""
    dir_path = _exp_dir(experiment_id)
    os.makedirs(dir_path, exist_ok=True)
    path = f"{dir_path}/round_logs.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state.get("round_logs", []), f, ensure_ascii=False, indent=2)
    return path
