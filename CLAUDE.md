# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**lgg_automation** is an AI-powered penetration testing automation framework using LangChain, LangGraph, and GPT-4o. It conducts autonomous red team exercises with:

- Multi-node LangGraph workflows with Worker-Critic feedback loops
- RAG (Retrieval-Augmented Generation) knowledge base of Metasploit techniques
- Direct control of Metasploit Framework and Linux terminal via SSH
- Real-time attack orchestration against target systems in controlled lab environments

## Commands

```bash
# Build/rebuild the RAG knowledge base (ChromaDB)
python build_database.py

# Run the main autonomous agent (interactive REPL)
python single_focus.py
```

No formal test suite, linting, or build configuration exists. Test files (`test.py`, `test_attack_tool.py`, `test_graphing.py`) are ad-hoc.

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
| `single_focus.py` | **Current main agent** - Worker/Critic loop, tool integration, state management |
| `refined.py` | **WIP** - Refactored agent with cleaner architecture (planned migration target) |
| `build_database.py` | RAG ingestion - processes PDFs, CSVs, YAML, Markdown into ChromaDB |
| `rag.py` | LangChain tool for knowledge base queries |
| `metasploit_tools.py` | Persistent Metasploit RPC console session management |
| `user_input.txt` | Attack prompts/objectives fed to the agent |

### Development Focus

Currently working in `single_focus.py`, planning migration to `refined.py` for better agent architecture. The refactor introduces:
- Functional `call_llm()` helper for cleaner LLM invocation
- Separate node functions (e.g., `planner_node`) for more modular graph structure

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

Hardcoded in `single_focus.py`:
- Kali machine: `192.168.34.6` (SSH port 22, MSF RPC port 55553)
- Credentials: `kali`/`kali`
- Model: `gpt-4o`

## Dependencies

No `requirements.txt` exists. Core dependencies (inferred from imports):
- `langchain`, `langgraph`, `langchain-openai`, `langchain-chroma`, `langchain-community`
- `chromadb`, `openai`, `paramiko`, `pymetasploit3`, `python-dotenv`, `msgpack`

## Agent Constraints

From system prompts in `single_focus.py`:

**Worker**:
- Must query knowledge base before attacking (intelligence phase)
- Must customize parameters (RHOSTS, LHOST, LPORT) from defaults
- Non-interactive commands only (no `ftp`, `ssh`, `vi`, `nano`)
- Success: "Command shell session X opened" or "Meterpreter session X opened"

**Critic**:
- Checks for persistence (tried multiple alternatives?)
- Returns "PASS" or "FAIL: [specific instruction]"
- Laziness = fixable error + giving up
