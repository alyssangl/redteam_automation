# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **New here? Read `HANDOFF.md` first** — it has the verified mental model, lab
> operations, landmines, and roadmap. The current pipeline is
> `core_agents/orchestrator.py` + `stages/*.py` on branch `graph-orchestrator`.
> The old `single_focus.py` is retired (now `legacy_agents/single_focus.py`).

## Project Overview

**lgg_automation** is an AI-powered penetration testing automation framework using LangChain, LangGraph, and GPT-4o. It conducts autonomous red team exercises with:

- Multi-node LangGraph workflows with Worker-Critic feedback loops
- RAG (Retrieval-Augmented Generation) knowledge base of Metasploit techniques
- Direct control of Metasploit Framework and Linux terminal via SSH
- Real-time attack orchestration against target systems in controlled lab environments

## Commands

```bash
# Run the offline test suite (no lab needed — do this before every commit)
python tests/run_offline.py

# Run a live scenario against the lab (bring the lab up first — see HANDOFF.md §4)
python experiments/live_test_continuum.py     # or live_test_proftpd.py, etc.

# Run the orchestrator directly on a graph
python -m core_agents.orchestrator examples/continuum_rce_graph.json
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

No `requirements.txt` exists. Core dependencies (inferred from imports):
- `langchain`, `langgraph`, `langchain-openai`, `langchain-chroma`, `langchain-community`
- `chromadb`, `openai`, `paramiko`, `pymetasploit3`, `python-dotenv`, `msgpack`

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
