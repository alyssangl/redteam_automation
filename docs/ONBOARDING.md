# ONBOARDING — lgg_automation / GRAFT

**For the two new students taking over the system.** This is the guided tour of
the code you'll be extending. It assumes you've seen the presentation (the *what*
and *why*); this doc is the *how* — the architecture, the two novel mechanisms in
detail against the real source, how to run it, and where to plug your own work in.

> Read `HANDOFF.md` right after this — it has the lab operations and the landmines
> (things that look like bugs but are lab state). `docs/DESIGN_PHILOSOPHY.md` has
> the reasoning behind the shape. This doc is the bridge between them and the code.

Everything below is verified against `core_agents/orchestrator.py` +
`stages/*.py` + `experiments/parse_eval.py` on the **`master`** branch (the single
active line — the old `graph-orchestrator` work was merged in). Line numbers are
approximate — trust the function names, `grep` if a number has drifted.

---

## 0. The one-paragraph mental model

You hand the system an **attack graph** (nodes = actions like "exploit UnrealIRCd",
edges = decisions like "if a session opened, go to privesc") and a **target IP** in
an isolated lab. A **backtracking walker** executes the graph node by node, driving
Metasploit and SSH against the target. When a node fails, two feedback layers kick
in: a lightweight **judge** (continue/adapt/escalate between nodes) and a heavyweight
**replanner** that mutates the graph (grows new nodes/edges). Every claimed success
is checked against **raw bytes captured off the target**, never the LLM's own word.
The research contribution sits on top of this: the **graft** (repairing a lost
*capability* structurally) and the **grounding oracle** (admitting success only on
captured evidence).

---

## 1. The research contribution — what makes this a paper, not just a tool

The system is the vehicle; these two ideas are the science. Internalize them first,
because everything you build should serve or extend one of them.

### C1 — The graft: capability loss ≠ technique failure

When an autonomous agent's step fails, there are **two fundamentally different
causes** that ordinary agents conflate:

- **Technique failure** — the *action* was wrong (wrong exploit module, wrong
  option). Fix: **substitute** a different technique and retry. Retrying is fine
  because the world state is intact.
- **Capability loss** — the *action* was fine, but a *precondition* the agent
  relied on is gone. The canonical case: your Meterpreter/shell **session dies**
  (network blip, target reboot, someone kills it). Now every downstream step that
  needed that session is **orphaned**. Retrying is **useless** — the session is
  still dead at every retry budget, so the precondition is unsatisfiable *by
  construction* (this is Eq. 6 in the paper, "capability orphaning").

The **graft** is the structural repair for capability loss: detect that a *held*
capability was lost, **re-provision** it (grow a fresh re-exploit node), and
**re-parent** the orphaned objective onto the fresh capability. Not a retry — a
graph mutation. §4 walks the code.

### C2 — The grounding oracle: success is defined over captured bytes

An LLM agent will happily report "I am now root" or "the file was written" when it
wasn't. If you let that self-report drive execution state, your whole run is built
on lies. The **grounding oracle Γ** admits a success **only if raw bytes the target
emitted prove it** — `uid=0(root)` in captured output for privesc, a written proof
marker read back off disk for impact. Never the agent's prose. The formal property
is **Δ_A = 0**: the oracle never admits an unproven claim into execution state. §5
walks the code.

---

## 2. The killchain and the 3-layer decision model

### 2.1 Five stages (`stages/`)

```
recon → initial_access → privesc → persistence → impact
(scan)   (get a session)  (get root) (stay in)   (do the objective)
```

Each stage is a **self-contained LangGraph subagent** — its own
Planner→Executor→Critic loop (some add Enumerator/Verifier). The orchestrator does
**not** run them linearly; the *graph* decides the shape and the walker can branch,
skip, backtrack, and grow new nodes.

| Stage | File | Internal roles | What to watch |
|---|---|---|---|
| recon | `stages/recon.py` | Planner→Executor→Critic | force-routed to subagent; top-ports-first, never `-p-` |
| initial_access | `stages/initial_access.py` | recon_parser→researcher→planner→parameter_solver→executor→critic | biggest file; 600s time-box; `[PROVEN]`-vector bias |
| privesc | `stages/privesc.py` | Enumerator⟷Planner⟷Executor→Critic | kernel path: upgrade shell→meterpreter, then overlayfs/dirtycow; critic uses `getuid`/`id` |
| persistence | `stages/persistence.py` | Planner→Executor→Verifier→Critic | session-type-aware; real pubkeys; mandatory FAIL when verification empty |
| impact | `stages/impact.py` | Planner→Executor→Critic | writes + reads-back proof artifacts; upgrades a command_shell→meterpreter first |

### 2.2 The 3-layer model (the design north star)

- **L1 Tactical** — the stage subagents. *Rule: tight kill-chain scope, broad
  tools/prompts inside it.* A stage attacks a real machine freely but never plans
  or orchestrates.
- **L2 Strategic** — `judge()` (`orchestrator.py` ~1578). Runs after a node
  completes / a failed retry; emits `continue | adapt | escalate`. `adapt` can
  rewrite a failing command via the LLM; `escalate` forces the replanner. Catches
  drift early so L3 fires less.
- **L3 Heavyweight** — `_replan_from()` (~2116). Graph mutation. The LLM emits a
  **tiny intent** `{action, target_hint, module_options?}` and code
  (`_expand_intent_to_node`, ~1876) expands it into a full node. **The graft lives
  here** (§4).

**The LLM enters at L2/L3, never inside the deterministic edge routing** — that's
what keeps runs replayable and auditable.

### 2.3 ⭐ The single most important runtime fact: direct path vs subagent path

Inside `_execute_node` (~2675) there is a fork:

- **Direct path (no LLM):** if a node carries a `module`/`commands_to_run`, run it
  straight over MSF/SSH. Fast, deterministic, cheap. Logged as `[direct]`.
- **Subagent path (LLM):** if a node is **goal-only** (no module/commands) — or a
  direct node whose execution *failed* while `explore=True` — dispatch to the stage
  subagent, which improvises within its scope. Logged as `[Dispatch]`.

**Why you care:** a graph full of prescribed modules mostly exercises the *direct
path*. To test a **subagent**, use a **goal-only** graph (the eval scenarios are
goal-only at the objective node exactly for this reason). If you "improved a
subagent" and nothing changed at runtime, you were probably on the direct path —
check the logs for `[direct]` vs `[Dispatch]`.

---

## 3. The graph engine and the walker

### 3.1 The graph (`core_agents/attack_graph.py`)

- **`AttackNode`** — one action. `agent_type` (recon/exploit/privesc/persistence/
  impact), a `goal`/`objective`, optionally a concrete `module` + options or
  `commands_to_run`, a `status`, and a `findings` dict (filled after execution).
- **`AttackEdge`** — a decision. A `condition` (ON_SUCCESS/…) and `checks`
  (`EdgeCheck(field, operator, expected)`, e.g. `session_id exists`). **Edge checks
  are hand-authored, deterministic, testable claims** — a strength; keep them. Only
  *LLM-grown* edges are lightweight `(source, target, rationale)`.
- Graphs **serialize to JSON** and **checkpoint** after each node, so an interrupted
  run resumes instead of restarting.
- You define graphs in `examples/*_graph.py` via `build_*_graph(target_ip,
  attacker_ip)`. `examples/orphan_c_graph.py` is the one to read first — it's the
  headline scenario and it's small.

### 3.2 The walker (`run_graph`, ~2790)

```python
run_graph(graph, checkpoint_path=None, explore=False, use_judge=True,
          pre_node_hook=None)
```

A **backtracking walker**: follow one path forward; on node failure, mark the edge
tried, backtrack to the predecessor, and (in `explore=True`) hand off to the
replanner. `ready_nodes()` uses `all()` over incoming edges, so the replanner can
unblock a node by adding/removing edges.

Two parameters matter for the research:
- `explore=True` — enables the subagent fallback **and** the replanner/graft. Every
  eval run uses it.
- `pre_node_hook` — a callback fired *before* each node executes. This is how
  **fault injection** works: the hook (from `experiments/fault_injection.py`) kills
  the session right before the orphaned node, simulating capability loss. Default
  `None` in production; errors are swallowed so a flaky injection can't crash a run.

### 3.3 How findings/sessions flow between stages

- Each stage returns a `Findings` TypedDict (`core_agents/state.py`):
  `ReconFindings`, `ExploitationFindings`, `PrivEscFindings`, etc.
- Downstream nodes read predecessors via
  `graph.gather_preceding_findings(node_id)` — **direct predecessors only**.
- `_find_session(preceding)` picks the session to hand a stage; it prefers the
  **most-escalated** successful session (root > sudo > user).
- **Gotcha:** if a stage doesn't put `session_id` in its findings, the session
  silently doesn't propagate. Every stage that opens/upgrades a session MUST surface
  `session_id`/`session_type`.

---

## 4. ⭐ Contribution 1 in code — the graft

This is the novel part. All of it is in `orchestrator.py`. Read this section with
the file open. The graft is a **loop across three pieces**: a history **H**, a gate
**F**, and a structural **repair**.

### 4.1 H — capability history (`_capabilities_from_findings`, ~1000)

After **every successful node**, the walker (~2952) records what capabilities that
node established into a running set `capability_history` (H):

```python
_new_caps = _capabilities_from_findings(node.findings)   # {"session", "session@root", "root", "artifact:/tmp/..."}
capability_history |= _new_caps
```

H is **monotonic** — it's "capabilities *ever* held", not "held now". That's the
whole trick: it lets the gate later distinguish a capability that was **lost** (in
H) from one that was **never established** (not in H). The alphabet is deliberately
small and session-centric: `session`, `session@<level>`, `root`, `artifact:<file>`.
Derived **only** from concrete finding fields (`session_id`, `new_level`,
`target_file`) — never prose, so H is as trustworthy as grounding.

### 4.2 F — the feasibility gate (`_feasibility_gate`, ~1121)

**Before** each node executes (~2932), F asks: *are the capabilities this node needs
actually live right now?*

- `_required_capabilities(node)` — pre(v). Post-access stages (privesc, persistence,
  impact, discovery) require a live `session`; recon/exploit require nothing (they
  *establish* capabilities). A graph can override with `metadata["preconditions"]`.
- `_world_capabilities(preceding)` — the **live** world state, **probed**. It holds
  `session` if **any** successful predecessor carries a session that is **still
  alive** (via `_session_alive`).
- `_feasibility_decision(required, world, history)` — the classification:

```python
missing = required - world
if not missing:            return True,  set(),   ""            # feasible
category = "capability" if (missing & history) else "precondition"
return False, missing, category
```

Two subtleties that cost real debugging (don't undo them):
- **`_session_alive` is presence-only** (is the id in `session.list`?). It does
  **not** echo-probe for responsiveness. A freshly re-provisioned reverse shell
  often answers an immediate echo empty, which would false-fail the gate and loop
  `F=0 → graft → F=0` forever. Responsiveness is the *stage's* job once the gate
  admits the node.
- **`_world_capabilities` holds `session` if ANY predecessor is live**, not just the
  first one `_find_session` would pick. Right after a graft the orphaned node has
  **two** predecessors (the dead original + the fresh re-exploit); picking only the
  first could land on the dead session and loop forever.

When F fails with `category == "capability"`, the walker (~2937) marks the node
`failure_category = "session_unusable"`, sets it FAILED, and **routes to repair
without executing**. That `session_unusable` tag is the signal the graft listens for.

### 4.3 The repair — revive + re-parent (`_reattach_session_unusable_nodes`, ~2059)

Inside the replanner (`_replan_from`), when a `session_unusable` node is present
(`_session_unusable_present`, ~2041, **gated on `eval_flags.graft_enabled()`**):

1. The replanner **grows a fresh re-exploit node** (same technique that opened the
   original session — the technique was never at fault).
2. `_reattach_session_unusable_nodes` **re-parents** every `session_unusable` node
   onto that re-exploit node (preserving the original inbound `session_id`-exists
   gate) and **resets them to PENDING** so the walker re-runs them.
3. On re-run, the orphaned node executes on the **fresh** session. Its stage's own
   live-session resolver (e.g. `impact._find_live_impact_session`) picks the live
   session even if `_find_session` still points at the stale one.

Why re-parenting is needed and a retry isn't: a dead **terminal** node (like
`file_drop`) has no successors to inherit, and a `new_edge` to a dead node is
refused — so without this explicit revive, the objective would be **silently
abandoned** after the re-exploit. The graft is what carries the objective across the
capability loss.

### 4.4 The NO-GRAFT ablation (the whole experiment hinges on this)

`_session_unusable_present` returns `False` when `EVAL_ENABLE_GRAFT=0`, **even if a
`session_unusable` node exists**. So the replanner routes the capability failure to
the ordinary technique-substitute path instead of the graft. That path **cannot
restore a lost session** → recovery collapses to **0/10**. FULL (graft on) recovers
**8/10**. That 8-vs-0, `p=0.0007`, **is** the measurement of C1. The ablation is a
minimal one-flag diff, which is what makes the contrast clean.

### 4.5 One live trace to hold in your head

```
recon ✓  → gain_access ✓ (session 1 opens; H gains "session")
[pre_node_hook kills session 1 before file_drop]
file_drop → F=0: required={session} world={} — "session" ∈ H → category=capability
          → mark session_unusable, FAILED, do not execute
replanner → session_unusable present (graft on) → grow re_exploit node
          → re-parent file_drop onto re_exploit, reset file_drop to PENDING
re_exploit ✓ (session 2 opens) → F passes: world={session}
file_drop ✓ on session 2 → writes marker, reads it back → GROUNDED → recovered
```

F fires exactly **once**, one graft, no loop. With `EVAL_ENABLE_GRAFT=0`, the
replanner never grows the re-exploit, session stays dead, `file_drop` never runs → 0.

---

## 5. ⭐ Contribution 2 in code — the grounding oracle

Everything here is in `experiments/parse_eval.py`. This file turns each finished run
(one `.log` + its `.json` checkpoint) into **one CSV row of reproducible metrics** —
never eyeballed, never the agent's own success claim.

### 5.1 The house rule (`_grounded`, ~211)

> A claimed success is GROUNDED **only if the raw bytes the target emitted prove
> it** — never a self-reported finding the stage set from its own claim.

`_grounded(node, log_text)` dispatches per stage:

- **privesc** (`_privesc_grounded`): a raw **root token** (`uid=0(root)` /
  `euid=0(root)` / `Server username: root`) must appear in captured output **and**
  co-occur with a ground-truth marker (`DIRECT ID CHECK`, `[direct]`, a docker
  rootbash probe…). This is what stops a plan line that merely *mentions*
  `uid=0(root)` from spoofing grounding — the token must ride on captured target
  output, not prose. Never `new_level` (that's circular — the stage sets it from its
  own claim).
- **impact** (`_impact_grounded`): the exact proof marker the run **wrote** must be
  **read back** in the OUTPUT of a read-back command (`cat`/`ls`/…). It parses the
  written literal from the `echo '<marker>' > file` command, then requires it to
  reappear in captured output. Handles both the direct-exec path and the subagent
  path (`[Tool Output]` lines).

### 5.2 The money metric — `false_success`

In `_parse_checkpoint` (~355): a node that claims `status == "success"` but is **not
grounded** is a false success. **Scope is deliberately narrow** — only privesc and
impact are counted (`_FALSE_SUCCESS_STAGES`), because only they have a **cheap
independent probe** (`id`/`getuid`; a marker read-back). Persistence grounding is
findings-derived (there's no cheap way to independently re-verify a landed
cron/ssh-key), so flagging it would rest on a circular check — a documented **threat
to validity (C5)**. This is why **orphan-B keeps a terminal impact node** to ground
on, instead of grounding on the persistence self-report.

**Result: `false_success = 0` across all 38 valid runs.** That's Δ_A = 0, measured.

### 5.3 The confounder machinery (why the numbers are trustworthy)

A run can fail for **lab reasons that aren't the system's behavior** — a wedged
msfrpcd console, a flaky target dropping nmap packets so recon fails and the whole
chain is skipped. `parse_eval` marks these `confounded` (via `_recon_or_root_failed`
+ log sentinels) and downstream tables **exclude** them. This is protocol, not
cherry-picking: exclusions are reported (2 of 40) and are not concentrated in the
claim variant. The harness also now snapshot-restores a fresh target per cell and
aborts a batch after consecutive confounded cells — the three failure modes we hit
while producing the data, now prevented.

---

## 6. The evaluation harness — how a result is produced end to end

```
experiments/run_matrix.py        # runs scenarios × variants × reps; per-cell target restore + lockfile
  → run_eval.py                  # PAPER_SCENARIOS / PAPER_VARIANTS / PAPER_REPS
  → each cell: run_graph(graph, explore=True) with the fault-injection pre_node_hook
  → writes logs/eval/<scenario>__<variant>__r<rep>.{log,json,stdout}
experiments/parse_eval.py        # the oracle: run artifacts → eval_results.csv (one row/run)
experiments/build_table.py       # eval_results.csv → reports/*.md tables
experiments/analyze_eval.py      # Wilson intervals + Fisher exact (pure Python, no scipy)
```

**Scenarios** (`examples/*_graph.py`, resolved by key via `ui/registry.py`):
- `orphan_c` — headline: kill the session before the **impact** objective.
- `flaw_privesc` — control: wrong exploit module at privesc (a *technique* failure).
- `orphan_b` — *scaffolded, unrun:* kill before **persistence** (a second placement).
- `baseline_impact` — no-fault T1 driver.

**Variants** (toggled by `core_agents/eval_flags.py`):
- `v0_full` — everything on.
- `v_nograft` — `EVAL_ENABLE_GRAFT=0` (the C1 ablation).
- `v3_noground` — `EVAL_GROUND_SUCCESS=0` (a C2 self-ablation).
- `v6_naive` — a single-loop baseline agent.

The clean campaign is `logs/eval/` (40 cells; see its `README.md`). Regenerate every
number with the three commands at the bottom of that README.

---

## 7. Running it (verified)

```bash
# OFFLINE tests — no lab. Run constantly; this is your safety net.
python tests/run_offline.py

# One scenario, offline graph build (no lab) — sanity-check a graph you wrote:
python -m examples.orphan_c_graph           # prints summary, writes the .json
#   run it with -m from the repo root; `python examples/orphan_c_graph.py` fails
#   with ModuleNotFoundError (the script dir, not the root, lands on sys.path).

# LIVE run of one scenario (needs the lab up — do HANDOFF.md §4.3 runbook first):
python -m core_agents.orchestrator examples/orphan_c_graph.json
#   watch logs/…  ; grep [Dispatch]/[direct]/[Replanner]/[Judge]/[F]/[H]

# The full campaign (hardened harness):
python experiments/run_matrix.py --scenarios orphan_c flaw_privesc \
    --variants v0_full v_nograft --reps 10 \
    --restart-target --abort-after-confounded 3
```

**Before any live run** do the HANDOFF.md §4.3 runbook (is the target up? restart
msfrpcd). If results look terrible, **check the log for 120s-per-command gaps
before you touch the code** — that's a wedged msfrpcd, not a regression.

---

## 8. Where to plug your work in (the open roadmap)

The paper has **C1 complete + significant** and **C2's soundness half proven**. The
open work, in the order I'd pick it up:

1. **orphan-B generality (already scaffolded).** `examples/orphan_b_graph.py` +
   `tests/test_orphan_b_graph.py` exist but are **unrun**. It kills the session
   before *persistence* — a second placement of the graft, with a terminal impact
   node so the recovered objective still grounds independently. It's a **stronger**
   test than orphan-C: the graft must re-parent a **two-node subgraph** (persist →
   file_drop), not a single leaf. **First live cell: confirm the graft re-parents
   the whole subgraph, not just `persist`** (that's the one new behavior it
   exercises). Then run it as a matrix (`--scenarios orphan_b --variants v0_full
   v_nograft --reps 10`).

2. **The C2 false-success spike via an external agent (HackingBuddyGPT).** C2's
   *complementary* half — "grounding OFF admits false claims" (Δ_A = Δ_R) — is not
   yet shown, because our own stages rarely overclaim. The right vehicle is a
   third-party agent that genuinely overclaims, run through **our oracle
   unmodified**. Concretely: give HBG an SSH foothold on MS3, capture its
   transcripts, and run its self-reported successes through `parse_eval._grounded`.
   **Cheap first step before any harness:** run HBG ~3× and read the transcripts —
   does it ever claim root when captured `id` doesn't show `uid=0`? If yes, the row
   is real; build the adapter. If HBG self-grounds, reconsider.

3. **More placements / more targets.** A second target model strengthens external
   validity (single lab / single target is the standing threat to validity).

### How to add each kind of thing

- **A new scenario:** copy `examples/orphan_c_graph.py`, change the chain +
  `metadata["injection"]`, add a `tests/test_<name>_graph.py` (mirror
  `test_orphan_c_graph.py`), and it's auto-discovered by `ui/registry.py`.
- **A new stage behavior:** it lives in the relevant `stages/*.py` subagent. Keep
  the scope tight; put safety in code, not prompt scolding (see
  `docs/DESIGN_PHILOSOPHY.md`). Add an offline test.
- **A new metric:** add it to `experiments/parse_eval.py` (compute it
  programmatically from the artifacts — never eyeball) and surface it in
  `build_table.py`. If it's a grounding metric, keep it **independent of the acting
  agent** (raw target bytes only), or it's not a grounding metric.

---

## 9. The rules that are not negotiable (or you'll reintroduce old bugs)

1. **Grounding is sacred.** Success is captured target bytes, never LLM prose. Every
   stage critic runs an independent ground-truth check. Don't "simplify" it away.
2. **Offline-first.** Almost every bug this project hit was a plumbing bug found only
   after a 20–40-min live run, then made into a 5-second unit test. Add to `tests/`
   for any new plumbing; run `tests/run_offline.py` before every commit.
3. **Failure is signal — don't pre-empt it.** Validate *structurally* + against the
   MSF catalog (does the module exist?); demote *semantic* gates (version matching)
   to advisory. Let wrong ideas run and fail — that failure is what the replanner
   needs.
4. **The LLM enters at L2/L3, never in edge routing.** Deterministic edges keep runs
   replayable. Only *grown* edges are LLM-authored.
5. **Small, revertible commits** (one logical change each). This is a standing
   request and it kept the history clean.
6. **Lab confounders masquerade as bugs.** Wedged msfrpcd, IP drift, target off. Do
   the §4.3 runbook; read the log for 120s gaps before blaming the code.

---

## 10. Where to read next

1. `HANDOFF.md` — lab operations + landmines (read now).
2. `docs/DESIGN_PHILOSOPHY.md` — *why* it's shaped this way; read before any
   structural change.
3. `reports/graft_results_summary.md` — the current results, written for Prof. Didik.
4. `examples/orphan_c_graph.py` + `experiments/parse_eval.py` — the two files that
   make the paper concrete; read them side by side.
5. `reports/refinement_history_v0_v19.md` — the evolution, if you want the backstory.
