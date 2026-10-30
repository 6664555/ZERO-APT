# ZERO-APT

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-39%2F39%20passed-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

> **语言：** [English](README.md) · [简体中文](README.zh-CN.md)

**论文：** [arXiv:2606.05567](https://arxiv.org/abs/2606.05567)

一个用于在**智能防御**下评估 LLM 渗透测试智能体的 **攻击者—防御者—裁决者（attacker–defender–judge）框架**。ZERO-APT 让一个多层 LLM 攻击者去对抗一个可配置的 LLM 防御者——后者从 Sysmon 遥测中实时检测攻击，同时还有一个裁决者在每一轮进行裁定，并在事后产出结构化的 CTI 报告。

ZERO-APT 不依赖 LLM 来保证多步攻击链的因果一致性，而是把一致性**下沉到系统架构**中：

- **规划—执行分离（Planning–execution separation）** — Planner → Dispatcher（两阶段）→ Executor，各司其职
- **多维 ReAct 反馈（Multi-dimensional ReAct feedback）** — 跨智能体（Attacker ↔ Judge）与智能体内（Executor 自纠错）两层循环
- **硬约束过滤动作库（Hard-constraint-filtered action library）** — 881 条后渗透动作（运行时库 v2；论文写作时为 775 条——库在持续扩充），带结构化前置条件，与环境状态做**机械**匹配（无 LLM 判断、无 PDDL 规划器）

---

## 亮点

| | |
|---|---|
| 🛡️ **可配置 LLM 防御者** | 三档强度（L1/L2/L3）：噪声注入、四条 Sysmon 签名规则（EID 1/3/11/12–14）、TTP 情报注入 |
| ⚖️ **机械裁决** | Judge 对 Defender 证据打 0–100 分，并在代码里与固定阈值（75）比较——分数与胜负永远不可能矛盾 |
| 🔒 **系统级硬约束** | 动作前置条件（权限 / 工具依赖 / 端口）在选择前通过表查找匹配；Executor 探测把不满足的条件翻为 `false`，下一轮机械排除依赖它的动作 |
| 🧭 **结构化回溯** | 被动（Judge 驱动、跨轮）与主动（Dispatcher 驱动、同轮、上限 3 次）回溯，带逐事件恢复记录 |
| 📋 **天生可审计** | 轮日志记录 Planner 计划/推理、Judge 推理、禁用动作演进、回溯触发、规则命中；事后生成 7 段式 CTI 报告，可选导出为 STIX 2.1 bundle（`CTI_FORMAT=stix`） |
| 🧪 **无需靶场即可跑** | 完整 dry-run 模式：mock LLM + 假适配器即可跑完多轮实验，零网络/零 VM 依赖 |
| 🎛️ **可插拔环境层** | WinRM 执行、ELK 日志接入、VM 快照重置、场景初始化都藏在四个适配器接口之后 |

## 快速开始

```bash
git clone <this-repo> && cd Zero-APT-Code
pip install -r requirements.txt   # 使用已装好依赖的 Python 3.10+ 解释器

# 1) Dry-run 验证（无需 API key、VM、ELK）
python tests/test_harness_dryrun.py

# 2) 全部单元测试（共 39 个；未装 stix2 时 test_stix_export 自动跳过）
python tests/test_core_mechanisms.py && python tests/test_defender_rules.py && python tests/test_metrics_stats.py && python tests/test_harness_dryrun.py && python tests/test_stix_export.py
```

### 运行真实实验

```bash
cp .env.example .env   # 填入 LLM key 与靶场目标
python main.py S1      # 以 S1 的默认防御档位运行
```

所有目标凭据都来自环境变量（`TARGET_IP`、`TARGET_USER`、`TARGET_PASSWORD`、…）——没有任何硬编码。LLM 后端通过 `LLM_TYPE` 选择（`deepseek` 默认、`claude`、或 `mock`）。

### 选择 LLM 后端

ZERO-APT 允许下载者选择任意 LLM，但接入成本取决于 API 形态：

- **`deepseek`（默认）** — OpenAI 兼容，配 `DEEPSEEK_API_KEY` 开箱即用。
- **`claude`** — 通过任意 OpenAI 兼容网关接入：设置 `CLAUDE_BASE_URL` 与 `CLAUDE_MODEL`（如 `claude-opus-4-6`）。Anthropic 原生 Messages API **不是** OpenAI 兼容格式，仓库未接入。
- **其它 OpenAI 兼容模型** — 改 `utils/llm.py` 里的模型字符串（`call_deepseek_api` / `call_claude_api`）。
- **非 OpenAI 兼容 API** — 需要你自己在 `utils/llm.py` 里新增客户端调用。

即：在仓库自带后端之间切换只需改配置；指向一个**不同的**服务商则要小改 `utils/llm.py`。

## 架构

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

## 实验

### 批量调度

```python
from harness.runner import run_batch
from core.interfaces import build_default_adapters

adapters = build_default_adapters(target_info)

plan = {
    "schemes":   ["zero-apt", "actionlib_off", "multireact_off"],  # 完整 + 2 个消融
    "scenarios": ["S1", "S2", "S3", "S4", "S5"],
    "tiers":     ["L1", "L2", "L3"],
    "reps":      20,
}
result = run_batch(plan, target_info, action_lib, action_index,
                   LLM_type="deepseek",
                   runner=adapters["runner"], log_source=adapters["log_source"],
                   resetter=adapters["resetter"], initializer=adapters["initializer"])
```

- `zero-apt` — 完整系统（机械硬约束过滤启用）
- `actionlib_off` — **−ActionLib** 消融：移除动作库，LLM 凭记忆生成命令
- `multireact_off` — **−MultiReAct** 消融：Planner+Dispatcher+Executor 合并为单层 ReAct，移除 Judge 闭环

每个实验向 `outputs/results/{run_id}.jsonl` 追加一行 JSON。每次重复前都会重置环境（VM 快照）并做场景初始化；实验间状态完全隔离。

### 指标与统计

```python
from harness.metrics import compute_experiment_metrics, aggregate
from harness.stats import chi2_yates, welch_t, friedman, pages_l, holm, wilcoxon

m = compute_experiment_metrics(state)   # 13 项指标：ASR, CCS*, CBF%, BSR, TP%, FP%, Rnd,
                                        # ActD, HCT, CoT, Rpt%, Time, ICC*   (* = 需人工评审)
```

论文用到的所有统计检验（带 Yates 校正的 χ²、Welch's t、Friedman、Page's L、Wilcoxon、Holm–Bonferroni、Cohen's d）都用纯 Python 实现，零第三方依赖，并对照已知分布分位数做了标定。

## 仓库结构

```text
core/            引擎：loop、state、hard_filter、defender_rules、judge_rules、
                 scenarios、interfaces（适配层）、archive_env
agents/          red（Planner/Dispatcher/Executor）、blue（Defender 档位）、
                 purple（Judge/Summary）、mono_react（消融）、prompts/
harness/         批量调度、13 项指标计算、统计检验、STIX 2.1 导出、假适配器
executor/        WinRM 命令执行、动作库（Rat_lib_v2.jsonl）+ 合并工具
utils/           LLM 后端（deepseek/claude/mock）、ELK 查询、日志、快照
tests/           5 个套件、39 个测试 —— 用快速开始里的命令全部运行
```

## 环境配置

| 变量 | 用途 |
|---|---|
| `DEEPSEEK_API_KEY` / `CLAUDE_API_KEY` | LLM API key（真实运行必需） |
| `LLM_TYPE` | `deepseek`（默认）/ `claude` / `mock` |
| `CLAUDE_BASE_URL` / `CLAUDE_MODEL` | Claude 后端的 OpenAI 兼容网关（Anthropic 原生 API 非 OpenAI 兼容） |
| `ELASTICSEARCH_URL` | 查询 Sysmon `winlogbeat-*` 的 ELK 端点（默认 `http://localhost:9200`） |
| `TARGET_IP` / `TARGET_USER` / `TARGET_PASSWORD` / `TARGET_HOSTNAME` / `TARGET_OS` / `TARGET_ADMIN_USER` | 攻击目标凭据 |
| `MISSION` | 可选的每次运行任务覆盖 |
| `CTI_FORMAT` | 事后报告格式：`markdown`（默认，仅 `.md`）/ `stix`（仅 `.stix.json`）/ `both`。`stix`/`both` 需要 `pip install stix2` |
| `VMWARE_RUN` / `VMX_PATH` | 可选的基于快照的环境重置 vmrun 路径 |

## 靶场要求（自备）

要对真实靶场运行，你需要在本仓库之外提供：Windows Server 2022 目标 VM（见论文基准说明）、把 Sysmon + winlogbeat 汇入 ELK、以及 WinRM 访问。实现或复用 `core/interfaces.py` 里的四个适配器（`CommandRunner`、`LogSource`、`EnvironmentResetter`、`ScenarioInitializer`）。

## 安全与伦理

本仓库仅用于**在已授权靶场上的安全研究与教育**。它**不**面向真实系统。完整负责任使用声明与漏洞上报方式见 [SECURITY.md](SECURITY.md)。仓库刻意不含任何硬编码凭据与 API key；请用 `.env` 配置你自己的环境。

## 许可证

MIT — 见 [LICENSE](LICENSE)。

## 引用

```bibtex
@misc{zeroapt,
  title  = {{ZERO-APT}: {A} Turn-Based Attacker-Defender-Judge Framework for
            Evaluating LLM Penetration Agents under Intelligent Defense},
  author = {Anlan Zheng and Tiantian Zhu},
  note   = {arXiv preprint, arXiv:2606.05567},
  year   = {2026}
}
```
