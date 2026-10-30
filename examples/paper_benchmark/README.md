# Paper Benchmark Example (real range, not mock)

This is a copy-and-adapt template for wiring ZERO-APT to **your own range**. The core engine (`core/`, `agents/`, `harness/`) is unchanged — you only do two things: fill in `config.yaml` and set the environment variables.

## Files

| File | Purpose |
|---|---|
| `config.yaml` | Paper benchmark config: two VMs, ELK, LLM backend, snapshot paths |
| `adapters.py` | The four **real** adapters: WinRM execution / ELK query / dual-VM snapshot revert / scenario initial conditions (S5 pre-block, S3 lateral) |
| `run_scenario.py` | Run a single scenario (`--check` only verifies the wiring, never touches the range) |
| `run_batch.py` | Run an experiment matrix — the `PLAN` dict is arbitrary; 1,400 is just one way to fill it |

## Four-step quick start

> Use a Python 3.10+ interpreter with the dependencies installed (e.g. `conda activate zero-apt`). A bare `python` without the deps (e.g. an untouched 3.14) will fail with `ModuleNotFoundError: requests`.

```bash
cd Zero-APT-Code                      # repository root

# 1) Offline wiring check (no range / no API key)
python examples/paper_benchmark/run_scenario.py S5 --check
python examples/paper_benchmark/run_batch.py --check

# 2) Fill config.yaml: absolute vmrun path, VMX paths for both VMs, snapshot name

# 3) Set environment variables (or .env)
export DEEPSEEK_API_KEY=sk-...        # LLM key
export TARGET_PASSWORD=...            # primary target initial-user password
export ELASTICSEARCH_URL=http://...   # ELK endpoint

# 4) Real run
python examples/paper_benchmark/run_scenario.py S5     # single scenario
python examples/paper_benchmark/run_batch.py           # batch matrix
```

## How to make it your own experiment

1. **Change the range** → edit `config.yaml` IPs/credentials/VMX paths; the four adapter implementations stay the same
2. **Change what is pre-blocked** → edit `PaperScenarioInitializer.S5_PRIMARY_BLOCK` in `adapters.py`, replacing `PsExec.exe` with the tool/port you want to block (goes through hard-condition flipping, so the Dispatcher automatically excludes actions that depend on it)
3. **Change the experiment matrix** → edit the `PLAN` dict in `run_batch.py`: `schemes`/`scenarios`/`tiers`/`reps` are all free
4. **Add Linux/container actions** → add entries to the action library (six-tuple schema, see the main README); the Dispatcher matching logic stays the same
