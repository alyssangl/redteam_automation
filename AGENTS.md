# AGENTS.md

Guidance for **any** AI coding agent (Claude Code, Cursor, Codex, Aider, …) working
in this repository. It's the tool-agnostic entry point; `CLAUDE.md` is the deep
index and `HANDOFF.md` is the full mental model. Read this first, then those.

## What this project is

**lgg_automation / GRAFT** — an AI-driven red-team automation framework (LangChain +
LangGraph + GPT-4o) that walks an *attack graph* against a target in a **controlled
lab**, backtracking and re-planning when stuck. It is a **research tool**, not a
product; nothing here runs in production.

> ⚠️ **Scope & safety — non-negotiable.** This code drives real exploitation
> (Metasploit/SSH) against an isolated lab (`192.168.34.7`). Only ever point it at
> machines you own in that lab. Never add a capability whose purpose is to widen
> targeting, evade detection, or run against anything outside the lab. Keep changes
> within authorized security-research scope.

## Where to read the real picture (in order)

1. `HANDOFF.md` — the one doc to read first: mental model, lab operations,
   landmines, roadmap. The lab section (§4) is knowledge that's only in this file.
2. `docs/ONBOARDING.md` — source-verified walkthrough of the two novel mechanisms
   (the **graft** and the **grounding oracle**) against the real code.
3. `docs/DESIGN_PHILOSOPHY.md` — *why* the system is shaped this way. Read before
   any structural change.
4. `CLAUDE.md` — lean index mapping "I need X" → the right file.

## Setup

- Python 3.10, conda env `red_teaming_auto_lamgchain` (or `docker compose` — see
  `REPRODUCIBILITY.md`). `pip install -r requirements.txt`.
- Requires `.env` with `OPENAI_API_KEY`.
- On Windows, prefix live runs with `PYTHONIOENCODING=utf-8`.

## Commands

```bash
python tests/run_offline.py                       # offline suite — NO lab needed; run before every commit
python experiments/live_test_flaw_privesc.py      # a live scenario (lab must be up — see HANDOFF.md §4.3)
python -m core_agents.orchestrator examples/orphan_c_graph.json   # run the orchestrator on a graph
python -m ui.cockpit                              # Textual TUI: launch + watch a run live (needs `textual`)
python database_utils/build_database.py           # rebuild the RAG knowledge base (ChromaDB)
```

`tests/` is the real offline suite. `experiments/test_stage_*.py` are ad-hoc, not
part of it.

## The rules that are not negotiable (breaking them reintroduces old bugs)

1. **Grounding is sacred.** Success = raw bytes captured off the target
   (`uid=0(root)`, a proof marker read back), never the LLM's own claim. Every stage
   critic runs an independent ground-truth check. Don't "simplify" it away.
2. **Offline-first.** Almost every bug here was a plumbing bug found only after a
   20–40-min live run. Add a 5-second unit test in `tests/` for any new plumbing and
   run `tests/run_offline.py` before committing.
3. **Failure is signal — don't pre-empt it.** Validate *structurally* + against the
   MSF catalog (does the module exist?); demote *semantic* gates (version matching)
   to advisory. Let wrong ideas run and fail — that failure is what the replanner
   needs.
4. **The LLM enters at L2/L3, never in deterministic edge routing.** Hand-authored
   `EdgeCheck`s keep runs replayable/auditable; only *LLM-grown* edges are
   lightweight `(source, target, rationale)`.
5. **Tactic deterministic / procedure LLM-creative / grounding deterministic.** Put
   safety in code, not prompt scolding. Don't over-regulate the stage prompts.
6. **Small, revertible commits** — one logical change each. This is a standing
   request and it keeps history clean.
7. **Lab confounders masquerade as bugs.** A wedged msfrpcd (every command taking
   ~120s), Kali IP drift, or a powered-off target look like regressions but aren't.
   Do the `HANDOFF.md` §4.3 runbook and read the log for 120s gaps before touching
   code.

## Working method for a misbehaving run

Classify the bug first: **logical** (unintended; bad code → patch it) vs **design**
(a bad outcome from a bad shape → rethink it, don't paper over it with code). Test
the fix on a single graph, then on all test graphs — including the deliberately
broken `examples/flaw_*` ones.

## Repo shape (start here)

- `core_agents/orchestrator.py` — the engine: `run_graph` walker, `judge()` (L2),
  `_replan_from` (L3), dispatch, `_find_session`.
- `core_agents/attack_graph.py` — AttackGraph/Node/Edge dataclasses + JSON + checkpointing.
- `stages/*.py` — the 5 L1 subagents (recon, initial_access, privesc, persistence, impact).
- `examples/*_graph.py` — attack-graph definitions (`goal_only`/`flaw_*`/`orphan_*` exercise the subagents).
- `experiments/` — live-test drivers, the eval harness (`run_matrix.py`, `parse_eval.py`), lab helpers.
- `tests/` — offline unit suite (your safety net).
- `ui/` — Textual cockpit to launch and watch a run live.
