# ZERO-APT

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-39%2F39%20passed-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

> **Language:** [English](README.md) · [简体中文](README.zh-CN.md)

**Paper:** [arXiv:2606.05567](https://arxiv.org/abs/2606.05567)

An **attacker–defender–judge framework** for evaluating LLM penetration-testing agents under *intelligent defense*. ZERO-APT pits a multi-layer LLM attacker against a configurable LLM defender that detects attacks in real time from Sysmon telemetry, with a judge that adjudicates every round and emits structured post-hoc CTI reports.

Instead of trusting the LLM to keep multi-step attack chains causally consistent, ZERO-APT moves consistency **into the system architecture**:

- **Planning–execution separation** — Planner → Dispatcher (two-phase) → Executor, each with distinct responsibilities
- **Multi-dimensional ReAct feedback** — inter-agent (Attacker ↔ Judge) and intra-agent (Executor self-debugging) loops
- **Hard-constraint-filtered action library** — 881 post-exploitation actions (runtime library v2; the paper reported 775 at time of writing — the library keeps growing) with structured preconditions, *mechanically* matched against environment state (no LLM judgment, no PDDL planner)

---

## Highlights

| | |
|---|---|
| 🛡️ **Configurable LLM Defender** | Three intensity tiers (L1/L2/L3): noise injection, four Sysmon signature rules (EID 1/3/11/12–14), and TTP intelligence injection |
| ⚖️ **Mechanical adjudication** | Judge scores Defender evidence 0–100 and compares against a fixed threshold (75) in code — score and verdict can never contradict |
| 🔒 **System-level hard constraints** | Action preconditions (privilege / tool deps / ports) are matched by table lookup before action selection; Executor probes flip unmet conditions to `false`, and the next round mechanically excludes dependent actions |
| 🧭 **Structured backtracking** | Passive (Judge-driven, cross-round) and active (Dispatcher-driven, same-round, capped at 3) backtracking, with per-event recovery records |
| 📋 **Auditable by design** | Round logs carry planner plans/reasoning, judge reasoning, forbidden-action evolution, backtrack triggers, and rule matches; a 7-section CTI report is generated post-hoc, optionally exported as a STIX 2.1 bundle (`CTI_FORMAT=stix`) |
| 🧪 **Runs without a lab** | Full dry-run mode: mock LLM + fake adapters execute complete multi-round experiments with zero network/VM dependencies |
| 🎛️ **Pluggable environment layer** | WinRM execution, ELK log ingestion, VM snapshot reset, and scenario initialization all sit behind four adapter interfaces |

## Quick Start

```bash
git clone <this-repo> && cd Zero-APT-Code
pip install -r requirements.txt   # use a Python 3.10+ interpreter with the deps installed

# 1) Dry-run verification (no API keys, no VMs, no ELK required)
python tests/test_harness_dryrun.py

# 2) All unit tests (39 total; test_stix_export auto-skips if stix2 is not installed)
python tests/test_core_mechanisms.py && python tests/test_defender_rules.py && python tests/test_metrics_stats.py && python tests/test_harness_dryrun.py && python tests/test_stix_export.py
```

### Running a real experiment

```bash
cp .env.example .env   # fill in LLM keys and lab targets
python main.py S1      # runs scenario S1 with its default defender tier
```

All target credentials come from environment variables (`TARGET_IP`, `TARGET_USER`, `TARGET_PASSWORD`, …) — nothing is hardcoded. The LLM backend is selected with `LLM_TYPE` (`deepseek` default, `claude`, or `mock`).

### Choosing an LLM backend

ZERO-APT lets the downloader pick any LLM, but the integration effort depends on the API shape:

- **`deepseek` (default)** — OpenAI-compatible, works out of the box with `DEEPSEEK_API_KEY`.
- **`claude`** — reached through any OpenAI-compatible gateway: set `CLAUDE_BASE_URL` and `CLAUDE_MODEL` (e.g. `claude-opus-4-6`). Anthropic's native Messages API is *not* OpenAI-compatible and is not wired in.
- **Any other OpenAI-compatible model** — change the model string in `utils/llm.py` (`call_deepseek_api` / `call_claude_api`).
- **A non-OpenAI-compatible API** — you'll need to edit `utils/llm.py` yourself to add the client call.

So: choosing between the shipped backends is config-only; pointing at a *different* provider means a small code edit in `utils/llm.py`.

## Architecture

```text
┌──────────────────────────  Round loop (core/loop.py)  ──────────────────────────┐
│                                                                                 │
│  Attacker ───────────────────────────► Defender ──────────────────► Judge       │
│  (agents/red.py)                        (agents/blue.py)           (agents/purple.py)
│  Planner                                ELK → 4 signature rules    evidence score vs 75
│    │ passive/active backtrack           L1: noise / L2: rules      (core/judge_rules.py)
│    ▼                                    L3: rules + TTP intel      winner → forbidden list
│  Dispatcher P1 (mechanical filter)                                     │
│    │  core/hard_filter.py               WinRM adapter                ▼
│    ▼  preconditions vs env state      LogSource adapter          state updates
│  Dispatcher P2 (mini-plan)                                          │
│    ▼                                                                ▼
│  Executor (ReAct, retry cap)      ──────►  next round  ◄────────────┘
│    │ probe → flip hard conditions
└────┴────────────────────────────────────────────────────────────────────────────┘
   CommandRunner adapter          EnvironmentResetter / ScenarioInitializer adapters
   (WinRM, cross-host creds)      (VM snapshots, S5 pre-blocking hooks)
```

## Experiments

### Batch scheduling

```python
from harness.runner import run_batch
from core.interfaces import build_default_adapters

adapters = build_default_adapters(target_info)

plan = {
    "schemes":   ["zero-apt", "actionlib_off", "multireact_off"],  # full + 2 ablations
    "scenarios": ["S1", "S2", "S3", "S4", "S5"],
    "tiers":     ["L1", "L2", "L3"],
    "reps":      20,
}
result = run_batch(plan, target_info, action_lib, action_index,
                   LLM_type="deepseek",
                   runner=adapters["runner"], log_source=adapters["log_source"],
                   resetter=adapters["resetter"], initializer=adapters["initializer"])
```

- `zero-apt` — full system (mechanical hard-constraint filtering active)
- `actionlib_off` — **−ActionLib** ablation: library removed, LLM generates commands from memory
- `multireact_off` — **−MultiReAct** ablation: Planner+Dispatcher+Executor merged into a single ReAct loop, Judge closure removed

Each experiment appends one JSON line to `outputs/results/{run_id}.jsonl`. The environment is reset (VM snapshot) and scenario-initialized before every repetition; per-experiment state is fully isolated.

### Metrics & statistics

```python
from harness.metrics import compute_experiment_metrics, aggregate
from harness.stats import chi2_yates, welch_t, friedman, pages_l, holm, wilcoxon

m = compute_experiment_metrics(state)   # 13 metrics: ASR, CCS*, CBF%, BSR, TP%, FP%, Rnd,
                                        # ActD, HCT, CoT, Rpt%, Time, ICC*   (* = human-expert)
```

All statistical tests used in the paper (χ² with Yates correction, Welch's t, Friedman, Page's L, Wilcoxon, Holm–Bonferroni, Cohen's d) are implemented in pure Python with no third-party dependencies, calibrated against known distribution quantiles.

## Repository Layout

```text
core/            engine: loop, state, hard_filter, defender_rules, judge_rules,
                 scenarios, interfaces (adapter layer), archive_env
agents/          red (Planner/Dispatcher/Executor), blue (Defender tiers),
                 purple (Judge/Summary), mono_react (ablation), prompts/
harness/         batch runner, 13-metric computation, statistical tests, STIX 2.1 export, fake adapters
executor/        WinRM command execution, action library (Rat_lib_v2.jsonl) + merge tooling
utils/           LLM backend (deepseek/claude/mock), ELK query, logging, snapshots
tests/           5 suites, 39 tests — run all with the commands in Quick Start
```

## Environment Configuration

| Variable | Purpose |
|---|---|
| `DEEPSEEK_API_KEY` / `CLAUDE_API_KEY` | LLM API keys (required for real runs) |
| `LLM_TYPE` | `deepseek` (default) / `claude` / `mock` |
| `CLAUDE_BASE_URL` / `CLAUDE_MODEL` | OpenAI-compatible gateway for the Claude backend (Anthropic's native API is not OpenAI-compatible) |
| `ELASTICSEARCH_URL` | ELK endpoint for Sysmon `winlogbeat-*` queries (default `http://localhost:9200`) |
| `TARGET_IP` / `TARGET_USER` / `TARGET_PASSWORD` / `TARGET_HOSTNAME` / `TARGET_OS` / `TARGET_ADMIN_USER` | Attack target credentials |
| `MISSION` | Optional mission override per run |
| `CTI_FORMAT` | Post-hoc report format: `markdown` (default, `.md` only) / `stix` (`.stix.json` only) / `both`. `stix`/`both` require `pip install stix2` |
| `VMWARE_RUN` / `VMX_PATH` | Optional vmrun paths for snapshot-based environment reset |

## Lab Requirements (bring your own)

To run against a real range you need to provide, outside this repo: Windows Server 2022 target VMs (see the paper's benchmark spec), Sysmon + winlogbeat shipping to an ELK stack, and WinRM access. Implement or reuse the four adapters in `core/interfaces.py` (`CommandRunner`, `LogSource`, `EnvironmentResetter`, `ScenarioInitializer`) — the engine never touches the lab directly.

## Security & Ethics

This repository is for **security research and education on authorized testbeds only**. It is **not** intended for use against real systems. See [SECURITY.md](SECURITY.md) for the full responsible-use declaration and how to report vulnerabilities. Hardcoded credentials and API keys are deliberately absent; use `.env` for your own environment.

## License

MIT — see [LICENSE](LICENSE).

## Citation

```bibtex
@misc{zeroapt,
  title  = {{ZERO-APT}: {A} Turn-Based Attacker-Defender-Judge Framework for
            Evaluating LLM Penetration Agents under Intelligent Defense},
  author = {Anlan Zheng and Tiantian Zhu},
  note   = {arXiv preprint, arXiv:2606.05567},
  year   = {2026}
}
```
