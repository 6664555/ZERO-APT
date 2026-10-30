"""examples/paper_benchmark/adapters.py — the paper benchmark's REAL adapters (not mock)

This is a copy-and-adapt template for "personalized use": fill your own range info into config.yaml
and this adapter set drives real WinRM execution + ELK detection + dual-VM snapshot revert +
scenario initial conditions. The engine (core/) is unchanged.

Usage: see run_scenario.py / run_batch.py / README.md.
"""

import os
import subprocess

from core.interfaces import CommandRunner, LogSource, EnvironmentResetter, ScenarioInitializer


class PaperCommandRunner(CommandRunner):
    """Real WinRM execution. Also resolves hostname -> IP (S3 lateral movement addresses the DataServer hostname)."""

    def __init__(self, target_info, host_registry=None):
        self.target_info = target_info
        self.host_registry = host_registry or {}

    def _resolve(self, target):
        return self.host_registry.get(target, target)

    def run_ps(self, command, target_ip="", user="", password=""):
        from executor.run_atomics import run_with_powershell, run_with_powershell_on_target
        if target_ip:
            return run_with_powershell_on_target(command, self._resolve(target_ip), user, password)
        return run_with_powershell(command, self.target_info)

    def run_cmd(self, command, target_ip="", user="", password=""):
        from executor.run_atomics import run_with_command_prompt, run_with_command_prompt_on_target
        if target_ip:
            return run_with_command_prompt_on_target(command, self._resolve(target_ip), user, password)
        return run_with_command_prompt(command, self.target_info)


class PaperLogSource(LogSource):
    """Real ELK query: fetch the last N minutes of Sysmon winlogbeat-* events from the configured endpoint."""

    def __init__(self, elk_url=None, index="winlogbeat-*"):
        self.elk_url = elk_url or os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
        self.index = index

    def get_logs(self, minutes=1):
        from utils.monitor_tools import get_logs
        # reuse the framework's ELK query (its ES_URL comes from the env var; override per config here)
        os.environ["ELASTICSEARCH_URL"] = self.elk_url
        return get_logs(minutes=minutes, index=self.index)


class PaperEnvironmentResetter(EnvironmentResetter):
    """Dual-VM snapshot revert (paper's two-VM topology), restoring the "ready" snapshot before each experiment."""

    def __init__(self, reset_cfg):
        self.vmrun = reset_cfg.get("vmrun", "")
        self.snapshots = reset_cfg.get("snapshots", [])

    def reset(self, scenario_id=""):
        if not self.vmrun:
            print("[resetter] vmrun not configured, skipping environment revert")
            return False
        ok = True
        for snap in self.snapshots:
            cmd = f'"{self.vmrun}" revertToSnapshot "{snap.get("vmx")}" "{snap.get("name", "ready")}"'
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if r.returncode != 0:
                print(f"[resetter] revert failed {snap.get('vmx')}: {r.stderr}")
                ok = False
        return ok


class PaperScenarioInitializer(ScenarioInitializer):
    """Paper scenario initial conditions (real implementation):
    - S3: lateral target DataServer ready (the range must ensure 192.168.1.102 is reachable)
    - S5: primary escalation path pre-blocked — use env_overrides to flip the primary-path tool
      False, so the next round's Dispatcher mechanically excludes actions depending on it,
      forcing the attacker to reroute (what S5 tests: backtrack recovery).
    """

    # Paper S5: primary path pre-blocked. The example uses PsExec as the blocked primary-path tool;
    # replace it with the tool/port you actually want to block on your range (same hard-condition flip).
    S5_PRIMARY_BLOCK = {"tools_unavailable": ["PsExec.exe"]}

    def __init__(self, lateral_ip=None):
        self.lateral_ip = lateral_ip

    def apply(self, scenario):
        sid = str(scenario.get("id", ""))
        if sid == "S3":
            return {"note": f"S3: DataServer ({self.lateral_ip or '192.168.1.102'}) ready for lateral movement",
                    "env_overrides": {}}
        if sid == "S5":
            return {"note": "S5: primary escalation path pre-blocked (PsExec.exe unavailable)",
                    "env_overrides": dict(self.S5_PRIMARY_BLOCK)}
        return {"note": f"{sid}: no special initialization", "env_overrides": {}}
