"""core/interfaces.py - external-dependency abstraction layer (range/WinRM/ELK/snapshot/scenario init)

The internal engine depends only on these four interfaces; external systems are wired in via
adapters:
- CommandRunner        : command execution (WinRM). Default wraps executor/run_atomics.py; dry-run uses FakeRunner.
- LogSource            : Sysmon log source (ELK/winlogbeat). Default wraps utils/monitor_tools.py; dry-run uses FakeLogSource.
- EnvironmentResetter  : environment reset before each experiment (VM snapshot revert). Default wraps utils/snapshot.py; returns False with an explanation when unconfigured.
- ScenarioInitializer  : scenario initial conditions (S5 primary-path pre-block, S3 second-host preparation). Default only emits a hint; the range integration supplies the concrete implementation, whose env_overrides merge into archive_environment.

For range integration, you only implement these four interfaces (or use the defaults + config);
the internal engine never changes.
"""

from typing import Any, Dict, List, Tuple


# ---- Interface definitions ----

class CommandRunner:
    """Command execution interface. Returns (output, exit_code)."""

    def run_ps(self, command: str, target_ip: str = "", user: str = "", password: str = "") -> Tuple[str, int]:
        raise NotImplementedError

    def run_cmd(self, command: str, target_ip: str = "", user: str = "", password: str = "") -> Tuple[str, int]:
        raise NotImplementedError


class LogSource:
    """Sysmon log-source interface. Returns a list of winlogbeat _source event dicts."""

    def get_logs(self, minutes: int = 1) -> List[Dict[str, Any]]:
        raise NotImplementedError


class EnvironmentResetter:
    """Experiment environment reset interface (VM snapshot revert, etc.). Returns True on success."""

    def reset(self, scenario_id: str = "") -> bool:
        raise NotImplementedError


class ScenarioInitializer:
    """Scenario initial-conditions interface. Returns {"note": str, "env_overrides": dict};
    env_overrides merge into that experiment's archive_environment (e.g. S5 pre-blocked hard-condition flips)."""

    def apply(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


# ---- Default implementations (wrapping existing modules, behavior unchanged) ----

class DefaultCommandRunner(CommandRunner):
    """Wraps executor/run_atomics.py WinRM execution. Local commands use target_info; remote use explicit credentials."""

    def __init__(self, target_info: Dict[str, Any] = None):
        self.target_info = target_info or {}

    def run_ps(self, command, target_ip="", user="", password=""):
        from executor.run_atomics import run_with_powershell, run_with_powershell_on_target
        if target_ip:
            return run_with_powershell_on_target(command, target_ip, user, password)
        return run_with_powershell(command, self.target_info)

    def run_cmd(self, command, target_ip="", user="", password=""):
        from executor.run_atomics import run_with_command_prompt, run_with_command_prompt_on_target
        if target_ip:
            return run_with_command_prompt_on_target(command, target_ip, user, password)
        return run_with_command_prompt(command, self.target_info)


class DefaultLogSource(LogSource):
    """Wraps utils/monitor_tools.py ELK query (ES_URL configured via ELASTICSEARCH_URL)."""

    def get_logs(self, minutes=1):
        from utils.monitor_tools import get_logs
        return get_logs(minutes=minutes)


class DefaultEnvironmentResetter(EnvironmentResetter):
    """Wraps utils/snapshot.py vmrun snapshot revert (returns False with an explanation when unconfigured)."""

    def reset(self, scenario_id=""):
        try:
            from utils import snapshot
            ok = snapshot.revert_snapshot("ready")
            if not ok:
                print(f"  [Resetter] snapshot revert failed (scenario={scenario_id}), continuing anyway")
            return ok
        except Exception as e:
            print(f"  [Resetter] snapshot tool unavailable ({type(e).__name__}), "
                  f"skipping environment reset (scenario={scenario_id})")
            return False


class DefaultScenarioInitializer(ScenarioInitializer):
    """Default implementation only emits hints; the range integration replaces it with a concrete one."""

    def apply(self, scenario):
        sid = str(scenario.get("id", ""))
        notes = []
        if sid == "S5":
            notes.append("S5: primary path pre-blocking must be applied by the range adapter "
                         "(e.g., ACL deny on the primary escalation path)")
        if sid == "S3":
            notes.append("S3: DataServer (192.168.1.102) must be prepared/reachable by the range adapter")
        return {"note": "; ".join(notes) if notes else "no scenario-specific initialization needed",
                "env_overrides": {}}


def build_default_adapters(target_info: Dict[str, Any] = None) -> Dict[str, Any]:
    """Build the default adapter set (range integration starting point)."""
    return {
        "runner": DefaultCommandRunner(target_info),
        "log_source": DefaultLogSource(),
        "resetter": DefaultEnvironmentResetter(),
        "initializer": DefaultScenarioInitializer(),
    }
