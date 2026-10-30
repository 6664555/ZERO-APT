"""harness/fake_adapters.py - dry-run adapters (full-loop acceptance without a range / without ELK)

FakeRunner     : command-execution echo mock, can script failures by substring
FakeLogSource  : returns a scripted Sysmon event list, can inject attack-feature events to exercise the Defender
NoopResetter   : environment reset no-op (dry-run has no VM)
PassInitializer: scenario initialization no-op
"""

from typing import Any, Dict, List

from core.interfaces import CommandRunner, LogSource, EnvironmentResetter, ScenarioInitializer


class FakeRunner(CommandRunner):
    """Command-execution echo mock. Commands containing any fail_substrings substring return exit code 1."""

    def __init__(self, fail_substrings=()):
        self.fail_substrings = tuple(fail_substrings)
        self.calls: List[Dict[str, Any]] = []

    def _run(self, command, target_ip, user, password):
        self.calls.append({"command": command, "target_ip": target_ip, "user": user})
        for s in self.fail_substrings:
            if s in (command or ""):
                return f"[mock] command failed (matched '{s}')", 1
        return f"[mock output] executed: {(command or '')[:120]}", 0

    def run_ps(self, command, target_ip="", user="", password=""):
        return self._run(command, target_ip, user, password)

    def run_cmd(self, command, target_ip="", user="", password=""):
        return self._run(command, target_ip, user, password)


class FakeLogSource(LogSource):
    """Returns a scripted event list. Benign events by default; can inject attack-feature events (e.g. a mimikatz parent-child) to trigger signature rules."""

    BENIGN_EVENT = {
        "@timestamp": "2026-10-28T10:00:00Z",
        "event": {"provider": "Service Control Manager"},
        "winlog": {"event_id": "7036"},
        "message": "Service Windows Update (wuauserv) entered running state",
    }
    ATTACK_EVENT = {
        "@timestamp": "2026-10-28T10:00:01Z",
        "event": {"provider": "Microsoft-Windows-Sysmon"},
        "winlog": {"event_id": "1"},
        "message": ("Process Create:\nRuleName: -\nUtcTime: 2026-10-28 10:00:01\n"
                    "Image: C:\\Windows\\System32\\mimikatz.exe\n"
                    "ParentImage: C:\\Windows\\System32\\cmd.exe"),
    }

    def __init__(self, events=None):
        self.events = list(events) if events is not None else [dict(self.BENIGN_EVENT)]
        self.calls: List[int] = []

    def get_logs(self, minutes=1):
        self.calls.append(minutes)
        return self.events


class NoopResetter(EnvironmentResetter):
    """dry-run: no VM to revert, returns True."""

    def __init__(self):
        self.calls: List[str] = []

    def reset(self, scenario_id=""):
        self.calls.append(scenario_id)
        print(f"  [Resetter] dry-run: environment reset skipped (scenario={scenario_id})")
        return True


class PassInitializer(ScenarioInitializer):
    """dry-run: applies no scenario initial conditions."""

    def apply(self, scenario):
        return {"note": f"dry-run: no scenario initialization for {scenario.get('id', '')}",
                "env_overrides": {}}


def build_dryrun_adapters(fail_substrings=(), log_events=None) -> Dict[str, Any]:
    """Build the dry-run adapter set, passed directly to run_experiment / run_batch."""
    return {
        "runner": FakeRunner(fail_substrings=fail_substrings),
        "log_source": FakeLogSource(events=log_events),
        "resetter": NoopResetter(),
        "initializer": PassInitializer(),
    }
