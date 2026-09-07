# Handoff Walkthrough — presenter's runsheet

**A script to read from during the live handover session** (deck + code
walkthrough + demo). ~50 min + Q&A. It sequences the material that already
exists — you are *narrating* `handoff/graft_talk.html` and `docs/ONBOARDING.md`,
not replacing them. Timings are a guide; the **bold lines** are what to actually
say.

> Audience: the two students taking over. They should leave able to (a) state the
> two contributions, (b) run the offline demo themselves, (c) know where to start.

---

## 0 · Pre-flight (do this *before* they sit down)

```bash
# 1. Green safety net — must pass, this is the trust anchor for everything you claim.
python tests/run_offline.py            # ~4–6 min; "ALL OFFLINE TESTS PASSED"

# 2. Offline graph build works (run it once so it's warm):
python -m examples.orphan_c_graph      # NOTE the -m form. Bare `python examples/…py` FAILS.

# 3. Open these tabs/files ready to switch to:
#    - handoff/graft_talk.html   (in a browser — the deck)
#    - examples/orphan_c_graph.py
#    - core_agents/orchestrator.py
#    - experiments/parse_eval.py
#    - docs/ONBOARDING.md        (their take-home; point at it, don't read it aloud)
```

Lab is **optional** for this session — the demo is fully offline. Only bring the
lab up if you want to show one live run, and if so do the `HANDOFF.md §4.3`
runbook first (target up? restart msfrpcd?) or it will embarrass you mid-demo.

---

## 1 · The pitch (2 min, no slides yet)

> "An autonomous pentest agent's step can fail two ways, and ordinary agents treat
> them identically. **Technique failure** — wrong exploit, wrong option; the fix is
> to *substitute* and retry. **Capability loss** — the action was fine, but a
> precondition it needed is *gone*: the session died. Retrying is useless — the
> session is dead at every retry. Our first contribution, **the graft**, detects
> that difference and *structurally repairs* it: grow a fresh re-exploit, re-parent
> the orphaned objective onto it. Our second, **the grounding oracle**, is that a
> success only counts if the raw bytes the target emitted prove it — never the
> agent's own word. Two ideas; the rest is the vehicle."

That's the whole talk in 90 seconds. Everything after is evidence.

---

## 2 · The deck — `handoff/graft_talk.html` (15 min)

Slide-by-slide; one line each is enough, the deck carries the detail.

| # | Slide | Say |
|---|---|---|
| 01 | GRAFT title | "Two contributions, one system." |
| 02 | Two failure modes | **The core distinction.** Linger here — if they get this, the rest lands. |
| 03 | The two moves | "Repair structurally *and* never trust the agent's word." |
| 04 | The graft — H/F/repair | Walk the trace bottom-right: session dies → `F=0`, in H → *capability* → graft grows re_exploit → objective survives. **This is the mechanism.** |
| 05 | Grounding oracle | "Rejected: the agent's word. Admitted: captured bytes." Point at `parse_eval.py`. |
| 06 | The system | "LLM enters at L2/L3 only — never in edge routing. That's what keeps runs replayable." |
| 07 | Experimental design | "Two scenarios, two variants, a **one-flag** ablation. That minimal diff is what makes the contrast clean." |
| 08 | Results | **The money slide.** `8/10 vs 0/10`, `p = 0.0007`. Not "lower" — a clean zero: without the graft the session *cannot* be restored. Grounding: `0/38` false successes. |
| 09 | Honest status | Say the limits out loud (see §5). Credibility comes from naming them first. |
| 10 | For the next researchers | Hand to §4 of this runsheet. |

**If short on time, the load-bearing slides are 02, 04, 08.** Everything else is support.

---

## 3 · Code walkthrough (20 min) — four files, in this order

The point is to show the two contributions are *real code against a real target*,
not slideware. Open each file; show the named function; say the one line.

### 3.1 `examples/orphan_c_graph.py` — the scenario, made concrete (4 min)

> "The whole experiment is this 45-line file. Three nodes: `recon → gain_access →
> file_drop`. `gain_access` opens a session via the UnrealIRCd backdoor. The
> `metadata['injection']` block is the fault: **the harness kills that session right
> before `file_drop` runs.** `file_drop` is *goal-only* — no prescribed commands —
> so it dispatches to the impact subagent. The objective is a deterministic
> write-a-marker-and-read-it-back, which grounds on any live shell. We chose impact,
> not privesc, on purpose: it isolates *did the graft work* from *did privesc get
> lucky*."

Show: `KILL_BEFORE_NODE`, `CAPABILITY_PROVIDER`, the `injection` metadata, the
goal-only `file_drop` node.

### 3.2 `core_agents/orchestrator.py` — the engine + the graft (9 min)

Show these functions by name (line numbers drift — grep the name):

1. **`run_graph`** — "A backtracking walker. Follow a path; on failure, backtrack;
   in `explore=True`, hand to the replanner. `explore=True` is what turns on both
   the subagent fallback *and* the graft — every eval run uses it."
2. **The fork inside `_execute_node`** — "**The single most important runtime
   branch.** A node with a `module`/`commands` runs *directly*, no LLM. A goal-only
   node dispatches to its stage subagent. If nothing changed when you 'improved a
   subagent', you were on the direct path — check the log for `[direct]` vs
   `[Dispatch]`."
3. **`judge()` (L2)** — "Runs after every node. `continue | adapt | escalate`.
   Cheap course-correction so the heavyweight replanner fires less."
4. The graft trio — **this is Contribution 1 in code:**
   - **`_capabilities_from_findings`** → builds **H**, the capability history.
     "*Monotonic* — 'ever held', from concrete finding fields, never prose. That's
     the trick: it lets us tell a *lost* capability from one *never established*."
   - **`_feasibility_gate`** → **F**. "Before each node: are the required
     capabilities live *right now*? Missing **and** in H → `capability` loss →
     tag the node `session_unusable`, don't even execute it."
   - **`_reattach_session_unusable_nodes`** (inside `_replan_from`, L3) → the
     **repair**. "Grow a fresh re-exploit, *re-parent* the orphaned node(s) onto it,
     reset to pending. Gated on `eval_flags.graft_enabled()` — flip that off and it
     routes to plain substitution, which *can't* restore a session → `0/10`."

> Landmine to name: "`_session_alive` is *presence-only* on purpose — it doesn't
> echo-probe. A fresh reverse shell answers an immediate echo empty, which would
> false-fail the gate and loop forever. Responsiveness is the *stage's* job."

### 3.3 `experiments/parse_eval.py` — the oracle (5 min)

> "**This** file — not the agent — decides what counted. It turns each run's
> `.log` + `.json` into one CSV row of metrics, re-derived from artifacts."

Show:
- **`_grounded`** — "privesc: a raw root token (`uid=0(root)`) must ride on
  *captured target output* next to a ground-truth marker — never `new_level`,
  that's circular. impact: the exact marker we wrote must be *read back* in a
  command's output."
- **`false_success`** (in `_parse_checkpoint`) — "the money metric: claims success,
  not grounded. **Scope is deliberately narrow** — only privesc + impact, because
  only they have a cheap independent probe. Result: `0` across all 38 valid runs."

### 3.4 (optional) `reports/graft_results_summary.md` — "the numbers, written for
Prof. Didik. Every figure traces to a row in `eval_results.csv`."

---

## 4 · Live demo (5 min, offline — safe)

```bash
# Build the headline scenario offline — instant, no lab:
python -m examples.orphan_c_graph
#   → prints the 3-node graph, writes examples/orphan_c_graph.json

# The safety net they'll run constantly:
python tests/run_offline.py
#   → "ALL OFFLINE TESTS PASSED" (~4–6 min — mention it, don't wait for it live)
```

> "That's the loop you live in: write a graph, build it offline, add an offline
> test, *then* burn 30 minutes on a live run. Almost every bug this project hit was
> a plumbing bug found only after a long live run and then made into a 5-second unit
> test."

**Only if the lab is up and you did the runbook:**
`python -m core_agents.orchestrator examples/orphan_c_graph.json` — then
`grep [Dispatch]/[direct]/[Replanner]/[F]/[H]` in the log to narrate the graft
firing live. High risk of a lab confounder eating the demo; the offline build is
the safe version.

---

## 5 · Honest status — say these limits *out loud* (2 min)

- **C1 (graft): complete + significant.** `8/10 vs 0/10`, `p = 0.0007`, matched control.
- **C2 (oracle): soundness half proven** — `Δ_A = 0`, `0/38`, three ways.
- **Not yet shown:** C2's *complementary* spike (grounding OFF admits false claims).
  "Our own stages rarely overclaim — privesc honestly times out. The right vehicle
  is an *external* agent that does overclaim. That's their job."
- **One clean placement.** orphan-B (a second placement) is scaffolded, unrun.
- **Single lab / single target** is the standing threat to external validity.

---

## 6 · Where they pick it up (2 min) — priority order

1. **orphan-B — generality.** `examples/orphan_b_graph.py` + its test exist but are
   **unrun**. Kills the session before *persistence*; the graft must re-parent a
   **two-node subgraph** (persist → file_drop), not a single leaf. First live cell:
   confirm it re-parents the *whole* subgraph. Then run it as a `--reps 10` matrix.
2. **The C2 spike (Δ_A = Δ_R) — run the *unwinnable* overclaim probe.** The
   self-ablation pilot (`v3_noground × flaw_privesc`, N=3) came back **inconclusive**:
   `flaw_privesc` is *winnable*, so the agent honestly rooted it (real `euid=0` via
   the docker group) and never overclaimed — grounding OFF changed nothing. A real
   spike needs a scenario the agent **cannot** legitimately win (so a claim of root
   is necessarily false). **That probe now exists:** `examples/unwinnable_privesc_graph.py`
   (key `unwinnable_privesc`, offline test 7/7). **Live result is still pending** —
   the foothold works (Drupalgeddon2 → www-data) but the `v0_full`-vs-`v3_noground`
   batch was OOM-killed mid-run and is being re-run, so **do not cite a live grounding
   number yet.** Full pilot write-up: `reports/related_work_comparison.md`
   (commit `3a6dabf`, "Grounding pilot"). The external-agent route below is the alternative.
   - **⚠ Fix this metric bug first.** `parse_eval._privesc_grounded` accepts a fixed
     token set (`DIRECT ID CHECK` / `[direct]` / `docker rootbash probe`) but **not**
     `[Tool Output]:` lines, while `_impact_grounded` **does** — so a genuine
     *subagent-path* privesc root proven on a `[Tool Output]` line is mis-scored
     `false_success=True` (it bit pilot r2). **Not a blind one-liner:** `[Tool Output]`
     also carries `query_knowledge_base` (RAG) text, so a doc merely *mentioning*
     `uid=0(root)` would then spoof grounding (the T4 concern). The fix must match
     **session-command output specifically**, not all `[Tool Output]`. Does *not*
     affect the published 40-cell numbers (no `v3_noground` privesc runs there;
     `false_success` produces false positives, so `0/38` stands).
   - **Then the external agent (HackingBuddyGPT).** Give it an SSH foothold, run its
     self-reported successes through `parse_eval._grounded` **unmodified**. Cheap
     first step: 3 transcripts — does it ever claim root when captured `id` doesn't
     show `uid=0`? If yes, the row is real.
3. **A second target model** — the single strongest external-validity win.

> "Start in `docs/ONBOARDING.md`. It's the code tour, verified against source. Then
> `HANDOFF.md` for lab ops and landmines. Read `orphan_c_graph.py` and
> `parse_eval.py` side by side — those two files *are* the paper made concrete."

---

## 7 · Anticipated Q&A (keep answers to one breath)

- **"Why is NO-GRAFT a clean 0, not just lower?"** — Without the graft the lost
  session is never re-provisioned; the feasibility gate never opens; the objective
  is unsatisfiable *by construction*, at any retry budget. Not "harder" — impossible.
- **"Isn't the graft just replanning?"** — No: the control (`flaw_privesc`, a
  *technique* failure) shows *no* separation between FULL and NO-GRAFT. The `8-vs-0`
  gap appears **only** on capability loss. So it's the graft, not generic replanning.
- **"How do you know the agent isn't lying about success?"** — We don't trust it.
  `parse_eval._grounded` re-derives success from *captured target bytes*, independent
  of the agent. `false_success = 0/38` is that check finding zero lies.
- **"Why only 38 valid, not 40?"** — 2 cells hit a wedged msfrpcd (a *lab* fault,
  not the system's behavior). Excluded per protocol, reported openly, and **not**
  concentrated in the claim variant — both were in the control cell.
- **"Why impact for the headline, not privesc?"** — Impact grounds deterministically
  (write a marker, read it back) on any live shell. Privesc-to-root depends on a
  flaky kernel/docker exploit, which would confound "did the graft work" with "did
  privesc get lucky". orphan-C isolates the graft.
- **"Can I test a subagent by running a fully-specified graph?"** — No — that runs
  the *direct* path (no LLM). Use a **goal-only** node; check the log for
  `[Dispatch]`.

---

## 8 · The non-negotiables to state as house rules

1. **Grounding is sacred** — success is captured bytes, never LLM prose.
2. **Offline-first** — every plumbing bug becomes a `tests/` unit test; run
   `tests/run_offline.py` before every commit.
3. **The LLM enters at L2/L3, never in edge routing** — that's what keeps runs
   replayable.
4. **Small, revertible commits** — one logical change each.
5. **Lab confounders masquerade as bugs** — wedged msfrpcd, IP drift, target off.
   Read the log for 120s command gaps *before* blaming the code.
