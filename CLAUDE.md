# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **New here? Read `HANDOFF.md` first** — it has the verified mental model, lab
> operations, landmines, and roadmap. The current pipeline is
> `core_agents/orchestrator.py` + `stages/*.py` on branch `graph-orchestrator`.
> The old `single_focus.py` is retired (now `legacy_agents/single_focus.py`).

### Where the detail lives (this file stays a lean index — go deep here)

| I need… | Read |
|---|---|
| The 5 subagents (roles, watch-fors) | `HANDOFF.md` §3 — the current-state index |
| Network / lab topology, IPs, creds, ports | `HANDOFF.md` §4 (lab reality + confounders) & §6 (config table); `REPRODUCIBILITY.md` (full setup + networking) |
| How findings/sessions flow between stages | `HANDOFF.md` §2.5 |
| Why it's built this way (3-layer model, etc.) | `docs/DESIGN_PHILOSOPHY.md` |
| The evolution / past design decisions | `reports/refinement_history_v0_v19.md`, `docs/plans/` |
| What's still open | `reports/refinement_roadmap.md` |

## Project Overview

**lgg_automation** is an AI-powered penetration testing automation framework using LangChain, LangGraph, and GPT-4o. It conducts autonomous red team exercises with:

- Multi-node LangGraph workflows with Worker-Critic feedback loops
- RAG (Retrieval-Augmented Generation) knowledge base of Metasploit techniques
- Direct control of Metasploit Framework and Linux terminal via SSH
- Real-time attack orchestration against target systems in controlled lab environments

## Design Philosophy

These principles are the grain of the codebase — build *with* them. Full reasoning
and the evolution story in **`docs/DESIGN_PHILOSOPHY.md`**; the design arc that
produced them is in `reports/refinement_history_v0_v19.md`.

1. **Three-layer decisions; the LLM enters in the middle.** L1 tactical (in-node
   ReAct loop) → L2 strategic (`judge()` between nodes: continue/adapt/escalate) →
   L3 heavyweight (`_replan_from` graph mutation). The LLM enters at **L2**, never
   inside the deterministic edge routing — that's what preserves replay/audit.
2. **Determinism where it counts.** Hand-authored `EdgeCheck`s are testable,
   deterministic claims — a strength; keep them. Only *LLM-grown* edges are
   lightweight `(source, target, rationale)`.
3. **Lower the emission bar.** Never make the LLM emit a full ~25-field AttackNode
   under stress — it emits a tiny `{action, target, hint}` intent; **code expands
   it** (`_expand_intent_to_node`). Audit which fields are actually load-bearing.
4. **Failure is signal — don't pre-empt it.** Validate *structurally* + against
   the MSF catalog (ground truth); demote *semantic* gates (version matching) to
   advisory. Let wrong ideas run and fail; that failure is what the replanner needs.
5. **Feed prose, not just typed findings.** Give judge/replanner the raw output an
   operator reads (nmap banners, stderr, exit codes), not only stripped summaries.
6. **Review every step, not only on failure.** `judge()` runs after every node on
   fresh context; alts and replan are parallel options it picks between, not a
   rigid `alts → replan → backtrack` sequence.
7. **Grounding beats prose.** Every stage critic verifies success against the
   target itself (`id`/`getuid` in the session, raw output as evidence, mandatory
   FAIL when unverified). Never let a stage claim success on its own say-so.
8. **Tight scope, rich capability inside it.** A stage stays precise to its
   kill-chain scope (no planning/orchestration bleed) but its tools/prompts are
   broad enough to attack a real machine freely — avoid "too formatted."

**Working method:** when a run misbehaves, first classify the bug —
**logical** (unintended; bad code → patch it) vs **design** (bad outcome from a
bad shape → rethink it, don't paper over with code). Test the fix on a single
graph, then on all test graphs (including the deliberately-broken `flaw_*` ones).

## Commands

```bash
# Run the offline test suite (no lab needed — do this before every commit)
python tests/run_offline.py

# Run a live scenario against the lab (bring the lab up first — see HANDOFF.md §4)
python experiments/live_test_flaw_privesc.py  # or live_test_baseline.py, etc.

# Run the orchestrator directly on a graph
python -m core_agents.orchestrator examples/orphan_c_graph.json
python -m core_agents.orchestrator --interactive

# Build/rebuild the RAG knowledge base (ChromaDB)
python database_utils/build_database.py
```

The `tests/` directory IS a real offline suite (run via `tests/run_offline.py`).
The `experiments/test_stage_*.py` files are ad-hoc, not part of that suite.

## Architecture

### Core Agent Workflow

```
User Input (attack objective)
    ↓
[LLM Node] - Strategic analysis + tool selection
    ↓
[Tool Node] - Execute (RAG | SSH Terminal | Metasploit RPC)
    ↓
[Critic Node] - Evaluate persistence & success
    ↓
FAIL (fixable) → Loop back (max 10 retries)
PASS → END
```

### Key Files

| File | Purpose |
|------|---------|
| `core_agents/orchestrator.py` | **Current main engine** — `run_graph` walker, `judge()` (L2), `_replan_from` (L3), stage dispatch |
| `core_agents/attack_graph.py` | AttackGraph/Node/Edge dataclasses + JSON (de)serialize + checkpointing |
| `core_agents/state.py` | Stage output contracts (Findings TypedDicts) |
| `stages/*.py` | The 5 L1 subagents (recon, initial_access, privesc, persistence, impact) |
| `examples/*_graph.py` | Attack graph definitions (`goal_only`/`flaw_*` exercise the subagents) |
| `experiments/live_test_*.py` | Live test drivers (one per scenario) |
| `database_utils/build_database.py` | RAG ingestion — PDFs, CSVs, YAML, Markdown into ChromaDB |
| `tools/rag.py` | LangChain tool for knowledge base queries |
| `tools/metasploit_tools.py` | Persistent Metasploit RPC console session management (lazy-connected) |
| `legacy_agents/single_focus.py` | **RETIRED** — the old linear Worker/Critic agent; do not use (`refined.py` was never built) |

### Development Focus

Active work is the **graph-driven orchestrator** (`core_agents/orchestrator.py` +
`stages/*.py`) on branch `graph-orchestrator` — a backtracking walker with a
2-layer feedback system (`judge()` + `_replan_from`) that replaced the old linear
`single_focus.py` pipeline. The 3-layer model (L1 stage subagents / L2 judge /
L3 replanner) and the full evolution are documented in `HANDOFF.md` and
`reports/refinement_history_v0_v19.md`.

### Agent Tools

1. **`query_knowledge_base`**: RAG lookup for exploitation techniques (requires verbose queries)
2. **`tool_linux_terminal`**: SSH command execution on Kali attacker machine
3. **`tool_metasploit_rpc`**: Interactive Metasploit console commands

### Token Management

- Compression triggered at >100,000 total characters in message history
- Individual messages >20,000 chars are LLM-summarized
- Latest turn preserved intact; earlier turns compressed while keeping IPs, CVEs, error codes

## Configuration

Environment variables in `.env`:
- `OPENAI_API_KEY` - Required for GPT-4o and embeddings

Hardcoded in `core_agents/common.py` (and duplicated in `stages/recon.py`,
`stages/initial_access.py` — grep when the lab moves; see `HANDOFF.md` §6):
- Kali machine: `192.168.34.6` (SSH port 22, MSF RPC port 55553)
- Credentials: `kali`/`kali`
- Models: replanner/judge `gpt-4o` (`orchestrator.py:66-67`), recon `gpt-4o`,
  initial_access + default `gpt-4o-mini` (`common.py:24`)
- Target IP `192.168.34.7` lives in each `experiments/live_test_*.py` and
  `examples/*_graph.py`

## Dependencies

Pinned in `requirements.txt` (versions verified in the `red_teaming_auto_lamgchain`
conda env, Python 3.10) — `pip install -r requirements.txt`. Direct deps only; pip
resolves the transitive tree. Core groups:
- LLM/graph: `langchain`, `langchain-core`, `langchain-community`, `langchain-openai`,
  `langchain-chroma`, `langchain-text-splitters`, `langgraph`, `openai`, `tiktoken`
- RAG vector store: `chromadb`
- Lab I/O: `paramiko`, `pymetasploit3`, `msgpack`
- Config + ingestion: `python-dotenv`, `pypdf`, `PyYAML`

## Agent Constraints

These Worker/Critic principles originated in the retired `single_focus.py` and now
live, per-stage, in each `stages/*.py` Planner/Executor/Critic (grounding,
non-interactive commands, and persistence-checking still apply):

**Worker**:
- Must query knowledge base before attacking (intelligence phase)
- Must customize parameters (RHOSTS, LHOST, LPORT) from defaults
- Non-interactive commands only (no `ftp`, `ssh`, `vi`, `nano`)
- Success: "Command shell session X opened" or "Meterpreter session X opened"

**Critic**:
- Checks for persistence (tried multiple alternatives?)
- Returns "PASS" or "FAIL: [specific instruction]"
- Laziness = fixable error + giving up
