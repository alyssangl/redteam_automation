# GRAFT — graph-driven red-team automation (`lgg_automation`)

An AI-driven penetration-testing framework (LangChain + LangGraph + GPT-4o) that
walks an **attack graph** against a target in a controlled lab — driving Metasploit
and SSH, and **backtracking / re-planning** when a step fails. It's a research
tool, not a product.

> ⚠️ **Lab-only.** This drives real exploitation against an isolated lab
> (Metasploitable 3). Only ever point it at machines you own in that lab.

## What "GRAFT" means — the two ideas

The framework is the vehicle; two mechanisms are the contribution:

- **The graft** — when a step fails, capability *loss* is not the same as technique
  *failure*. If your session dies, retrying the same technique is useless (the
  precondition is gone). The graft is the **structural repair**: detect the lost
  capability, grow a fresh re-exploit node, and **re-parent** the orphaned objective
  onto it — a graph mutation, not a retry.
- **The grounding oracle** — a claimed success counts **only if raw bytes the target
  emitted prove it** (`uid=0(root)` in captured output, a proof marker read back off
  disk), never the LLM's own say-so.

The architecture is a 3-layer decision model: **L1** stage subagents (recon →
initial_access → privesc → persistence → impact), **L2** a between-node `judge()`
(continue/adapt/escalate), **L3** a heavyweight `_replan_from()` that mutates the
graph. See `docs/ONBOARDING.md` for both mechanisms against the real code.

## Installation

Full setup (Docker framework + Kali, the Vagrant MS3 target VM, and networking) is
in **[`REPRODUCIBILITY.md`](REPRODUCIBILITY.md)** — start there. The short version:

```bash
# 1. Configure — set OPENAI_API_KEY; lab endpoints (KALI_IP/TARGET_IP/creds) default sensibly
cp .env.example .env

# 2. Framework + Kali attacker (containers)
docker compose build
docker compose up -d kali                                   # fresh msfrpcd each up (lab hygiene)
docker compose run --rm app python tests/run_offline.py     # sanity — no lab needed

# 3. RAG knowledge base (once; uses OpenAI embeddings)
docker compose run --rm app python database_utils/build_database.py

# 4. Target VM (kernel privesc needs a real guest kernel — keep it a VM, not a container)
vagrant up                                                  # Metasploitable 3 at TARGET_IP
```

Running the framework directly (no containers) instead: Python 3.10 (conda env
`red_teaming_auto_lamgchain`), `pip install -r requirements.txt`, then a `.env`
with `OPENAI_API_KEY`. Networking notes (container ↔ VM) are in `REPRODUCIBILITY.md`.

## Running it

```bash
python tests/run_offline.py                                 # offline suite — run before every commit
python experiments/live_test_flaw_privesc.py                # a live scenario (lab up first)
python -m core_agents.orchestrator examples/orphan_c_graph.json   # run the orchestrator on a graph
python -m ui.cockpit                                        # Textual TUI: launch + watch a run live
```

## Docs

| Read | For |
|---|---|
| [`HANDOFF.md`](HANDOFF.md) | **Start here** — mental model, lab operations, landmines, roadmap |
| [`docs/ONBOARDING.md`](docs/ONBOARDING.md) | The graft + grounding oracle walked against the source |
| [`docs/DESIGN_PHILOSOPHY.md`](docs/DESIGN_PHILOSOPHY.md) | *Why* it's shaped this way — read before structural changes |
| [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) | Stand up the whole lab from scratch |
| [`AGENTS.md`](AGENTS.md) / [`CLAUDE.md`](CLAUDE.md) | Guidance for AI coding agents working in this repo |
