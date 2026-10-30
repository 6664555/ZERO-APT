from typing import TypedDict, List, Optional, Dict, Any, Literal


class RoundLog(TypedDict, total=False):
    round: int
    red_feedback: str                # Attacker action text summary
    red_commands: List[Dict[str, Any]]  # Specific command sequence
    blue_feedback: str               # Defender detection result
    purple_judgement: str            # Judge adjudication conclusion
    winner: str                      # Judge mechanical verdict (blue_evidence_score vs 75)
    blue_evidence_score: int         # Judge score of the Defender evidence (0-100)
    hct_events: List[Dict[str, Any]] # This round's mechanical hard-constraint exclusions (HCT metric source)
    blue_rule_matches: List[Dict[str, Any]]  # Defender signature rule hits (TP/FP attribution source)

class GlobalState(TypedDict):
    # Main loop control
    loop_count: int
    max_loops: int
    should_continue: bool

    # Mission and goal
    mission: str                     # Overall mission description
    goal_achieved: bool              # Whether the Planner declared the goal achieved

    # ---- Two-level planning: subgoal queue (stack-like, implicit DAG) ----
    subgoals: List[str]              # Subgoals yet to execute
    current_subgoal: Optional[str]   # Currently active subgoal
    attempted_actions_by_subgoal: Dict[str, List[str]]  # Action IDs already tried per subgoal

    # ---- Environment state (hard conditions + soft-condition discoveries) ----
    archive_environment: Dict[str, Any]
    # Initialized with all predefined hardware/software dependencies, all values are None,
    # manually modified at runtime.
    # At runtime, progressively updated by Executor: hard conditions (privilege, services)
    # probed as True/False, soft conditions (file paths, parameter values) filled with values.

    # ---- Judge-maintained forbidden actions table (hard filter) ----
    forbidden_actions: List[str]     # Action IDs blocked by the Defender

    # ---- Judge mechanical verdict (blue_evidence_score vs threshold 75, see core/judge_rules.py) ----
    winner: str
    blue_evidence_score: Optional[int]

    # ---- Hard-constraint mechanical filter audit (HCT metric source) ----
    hct_events: List[Dict[str, Any]]

    # ---- Defender input (information isolation) ----
    blue_input_logs: Optional[str]   # Sysmon raw logs, Defender only reads this field
    blue_rule_matches: List[Dict[str, Any]]  # This round's signature rule hits (L2/L3)

    # ---- Output of each team in the current round ----
    red_feedback: str
    blue_feedback: str
    purple_feedback: str

    # ---- CTI cumulative logs ----
    round_logs: List[RoundLog]

class RedTeamInternalState(TypedDict):

    mini_plan_steps: List[Dict[str, Any]]
    current_step_index: int
    local_environment_cache: Dict[str, Any]

    executed_commands: List[Dict[str, Any]]
    last_command: Optional[str]
    last_output: Optional[str]

    retry_count: int
    max_retries: int                       # default 3, can be overridden by the Builder

    analysis_feedback: str                 # Executor's analysis of this round's success/failure

class Target_info(TypedDict): # Target info, for the Attacker to reference when generating commands
    hostname: str # set manually before the experiment, may not be needed
    ip_address: str # set manually before the experiment (env var TARGET_IP)
    os_version: str # set manually before the experiment, default windows server 2022
    user_name: str # initial-privilege user (env var TARGET_USER)
    password: str # initial-privilege user password (env var TARGET_PASSWORD, not committed)
    admin_name: str # admin user, default Administrator
    admin_password: str # admin user password, default empty


# Note for CLAUDE:
# This part is a reference template. It should be sufficient for general use. It's better to
# be redundant than to miss any key functional fields. You can supplement or modify on this
# basis. The principle is: better to have more than to miss something. Extra parts won't
# affect functionality, they just make the code less concise. But if something is missing,
# it's a problem.
