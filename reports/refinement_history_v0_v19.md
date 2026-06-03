# Stage / Subagent Refinement History — v0 → v19

The evolution of the graph-orchestrator pipeline and its five stage subagents
(`recon`, `initial_access`, `privesc`, `persistence`, `impact`) on branch
`graph-orchestrator`. Each entry records **the problem we hit**, **the design we
chose to fix it**, and the commit. This is the consolidated narrative; the raw
run-by-run table lives in `stage_refinement_cycle_log.md` and the open work in
`refinement_roadmap.md`.

## The method

An output-driven dev loop against **Metasploitable 3** (Linux ubuntu1404, target
`192.168.34.7`) via **Kali** (`192.168.34.6`):

> run an example graph → read what each stage actually did → refine one worker
> per stage (tight kill-chain scope, broad tools/prompts) → commit the version →
> re-test.

**Architecture primer (why some graphs test the subagents and others don't):**
a node that carries a `module`/`commands_to_run` runs the **no-LLM direct path**;
only *goal-only* nodes — and, since `e0e350a`, *failed* direct nodes in explore
mode — reach the stage **subagent**. So `success`/`proftpd` graphs only exercise
`recon` as a subagent; the `goalonly`/`flawed` graphs are what actually drive
`exploit`/`privesc`/`persistence`/`impact`, and that is where the real defects
surfaced.

The pipeline matured toward the 3-layer model from `Lessons from VulnBot.pdf`:
**L1 tactical** (inside-node ReAct loops = the stage subagents), **L2 strategic**
(`judge()` between nodes), **L3 heavyweight** (`_replan_from` graph mutation).

---

## Summary

| Ver | Problem | Design | Commit |
|----|---------|--------|--------|
| v0 | recon never converged (`-p-` scans → `recursion_limit` ×3); pipeline died in recon | — (baseline) | — |
| v1 | downstream stages never reached; blind repeats; giving-up counted as success | converge recon (top-ports-first, catch `GraphRecursionError`, always return findings) + contract-safe robustness across all 5 stages | `9b94626` |
| v2 | false success — stages reported PASS on unverified/hallucinated results | grounded verification: run `id` *in the session*, attach raw tool outputs as evidence, mandatory FAIL when unverified | `54d42aa` |
| arch | exploit/privesc/persist/impact were near dead code (direct fail just returned) | **direct→subagent fallback**: a failed direct node hands off to its stage subagent before walker/replanner; + `flawed_graph` | `e0e350a` |
| v3 | an unstable session died before privesc → "session no longer active" abort | liveness-probe before claiming success; `session.list` health check + swap to a live substitute session; honest fail | `78fad34` |
| v4 | an unbounded MSF call hung the whole run 12+ min | wall-clock cap on **every** MSF/SSH/session call + capped attempts | `0a6ce22` |
| v5 | privesc 400 crash: `tool` msg without preceding `tool_calls` (window slicing) | partial pair-safe message windows | `5cef3b0` |
| v6 | crash persisted on **parallel** tool_calls | **id-aware atomic `_make_pair_safe`** (keep an AIMessage only if every tool_call_id has a matching ToolMessage) + recursion headroom | `af0d816` |
| v7 | exhaustive privesc blew the 40-min clock | `PRIVESC_WALLCLOCK_TIMEOUT=300s` time-box (soft) + escalate `max_retries=1` | `7563ad4`, `acd66b6` |
| v8 | importing any module connected to msfrpcd (coupled to the lab) | **lazy MSF connection** — connect on first use, not import; unblocks offline tests | `d0c50ef` |
| v9 | logic/plumbing bugs only caught after 20–40-min live runs | **offline test suite** (`tests/run_offline.py`) + fixed full-port-scan recon hints (10 graphs) | `716aeb7` |
| v10 | deterministic failures burned identical retries | category-aware retry seed (`_is_retryable_failure`): short-circuit deterministic/exhausted failures to replan | `63dbad2` |
| v12 | exploit subagent ground 40 min on a failing vector (no time-box) | `EXPLOIT_WALLCLOCK_TIMEOUT=600s` — mirror v7 in `run_exploitation` | `3ca6b58` |
| v13 | **P0** direct path reported success on "permission denied" (no verification) | capture session **stderr** so the failure scanner sees denied writes / missing files | `185f187` |
| v14 | **P1** replanner re-routed to a non-retryably-dead node (escalate loop) | track non-retryable-dead nodes; never re-route to them — go to the objective | `3d88e92` |
| v15 | **P2** privesc only tried manual vectors, never the kernel path | PLANNER/EXECUTOR prompts: upgrade command_shell→meterpreter, run suggester + overlayfs/dirtycow early | `6f732e7` |
| v16a | the kernel path was half-wired — the **Enumerator** still skipped the suggester on a command_shell (= every session here) | Enumerator upgrades to meterpreter FIRST, runs the suggester, surfaces the new session id + suggested exploits | `605b7e5` |
| v16b | a rooted/upgraded privesc session never reached impact (`PrivEscFindings` had no `session_id`); privesc→impact got gated → replanner churn | propagate the newest **live** escalated session; `_find_session` prefers the most-escalated session | `0120c92` |
| v16c | the critic grounded on `id`, which **meterpreter rejects** → a rooted kernel session was falsely FAILed | session-type-aware `_direct_priv_check` (`id` for shell, `getuid` for meterpreter) + grounding-rule update | `e287af5` |
| v17 | exploit fallback ground params on an unproven module instead of pivoting to a known-good one (continuum/drupal time-box) | researcher tags `[PROVEN]` vectors; planner selects a non-banned `[PROVEN]` vector on retry/fallback | `5b1caa9` |
| v18 | replanner couldn't retry a credential attack with **different creds** (module-only anti-repeat ban; no creds slot) | `_config_key` (module+options) anti-repeat; intents carry `module_options`; failed creds surfaced; broadened `auth_failed` | `93aabba` |
| v19 | nothing told the replanner to rotate credentials before switching vectors | REPLAN_PROMPT nudge: on `auth_failed`, rotate creds on the same module first | `05530bc` |

---

## Phase 1 — make it run, make it honest (v0–v2)

**v0 (baseline).** recon's planner↔executor↔critic looped to LangGraph's
`recursion_limit=50` on all three retries — full `-p-` nmap scans timed out and
the pipeline died before any downstream stage ran.

**v1 — convergence + contract-safe robustness (`9b94626`).** recon: catch
`GraphRecursionError`, top-ports-first (no `-p-` in phase 1), SSH-timeout
handling, a critic hard-cap that emits partial findings, *always* return
findings. The other four stages got the same hardening pass: act on
`failure_category` instead of blind repeats, anti-repeat guards, and a
`FAIL_EXHAUSTED` verdict so **giving up ≠ success**. Result: both test graphs ran
the full chain end-to-end.

**v2 — grounded verification (`54d42aa`).** The first `goalonly` run exposed
*false success*: stages trusted their own prose. Fix: run `id` **inside the
session** (not the Kali console) for the real access level; attach raw tool
outputs as grounded evidence so the critic can't be fooled; mandatory FAIL when
verification is empty; real artifacts (e.g. a real pubkey, not a placeholder).

**arch — direct→subagent fallback (`e0e350a`).** Discovery: the non-recon
subagents were nearly dead code — every node carried a module/commands → direct
path, and a direct *failure* just returned without ever invoking the subagent.
Fix: in explore mode a failed direct node now hands off to its stage subagent to
improvise within scope before the walker/replanner escalates. Validated by
`flawed_graph` (a closed-port prescribed exploit → subagent improvised a session
via UnrealIRCd).

## Phase 2 — resilient, bounded, crash-free (v3–v6)

**v3 — session-loss recovery (`78fad34`).** The v2 goalonly run landed an
*unstable* UnrealIRCd-backdoor session that died before privesc. Fix:
liveness-probe a session before declaring success (dead ⇒ honest FAIL, killing
the phantom PASS); replace the 60s console check with an instant `session.list`
RPC health check; on a dead session, find and **swap to** a live substitute on
the target instead of aborting; anti-repeat keyed on (module, TARGETURI) so it
sweeps URIs.

**v4 — bound every tool call (`0a6ce22`).** The v3 goalonly run **hung 12+ min**:
a single `proftpd_modcopy_exec` blocked with no timeout. This was the real cause
of "why is it so slow" — not thoroughness, an unbounded tool call. Fix: a
wall-clock cap on every MSF console/RPC/session command (returns a failure string
on timeout, never blocks) + capped attempt counts. Hangs eliminated (recon 67s,
gain_access 84s). But v4's large privesc refactor introduced a regression…

**v5 / v6 — pair-safe message windows (`5cef3b0`, `af0d816`).** privesc began
crashing every attempt with OpenAI 400 *"messages with role 'tool' must be a
response to a preceding message with 'tool_calls'"* — window slicing orphaned
ToolMessages. v5 made the windows partially pair-safe; the crash persisted on
**parallel** tool_calls. v6's fix is the durable one: **id-aware atomic**
`_make_pair_safe` — an assistant `tool_calls` message is kept only if **every**
`tool_call_id` has a matching ToolMessage in the following run, else the whole
group is dropped. Plus recursion headroom for the bounded ReAct sub-loops
(persistence 100→250, privesc 120→200, impact 80→150). **Privesc crash
eliminated** (R6: 0 crashes); escalate now runs honestly but exhausts vectors
against a non-root user — a thoroughness-vs-speed tuning item → v7.

> **Net arc v0→v6:** crash-loops → works end-to-end → honest (grounded) →
> resilient (session recovery + fallback) → bounded (no hangs) → crash-free
> (id-aware pair-safe).

## Phase 3 — time-boxes, offline tests, generalization (v7–v12)

**v7 — escalate time-box (`7563ad4`, `acd66b6`).** `PRIVESC_WALLCLOCK_TIMEOUT=300s`
(soft — checks between stream steps, overshoots ~450s) + escalate `max_retries=1`
(a deterministic timeout isn't worth retrying).

**v8 — lazy MSF connection (`d0c50ef`).** Importing any stage connected to
msfrpcd at import time, coupling everything to a live lab. `_LazyMsfSession`
defers the connection to first use → offline imports/tests become possible.

**v9 — offline test suite (`716aeb7`).** Almost every bug so far was a
logic/plumbing bug found only after a 20–40-min live run. Added `tests/` pure-logic
checks (pair-safe, graph shapes, lazy-MSF, retry policy) runnable with no lab,
plus fixed full-port-scan recon hints across 10 graphs.

**v10 — category-aware retry seed (`63dbad2`).** `_is_retryable_failure`:
deterministic/exhausted failures (time-boxed escalate, `FAIL_EXHAUSTED`)
short-circuit to replan instead of burning identical retries.

**v11 generalization batch + v12 (`3ca6b58`).** proftpd 83%, unrealircd 80%,
samba 80% (fallback-recovered) completed; **continuum/drupal timed out at 40 min**
because `run_exploitation` had no time-box and ground a failing vector instead of
pivoting. v12 mirrors v7's time-box (`EXPLOIT_WALLCLOCK_TIMEOUT=600s`). Two
findings carried to the roadmap: (a) the fallback should prefer a **proven**
vector over grinding unproven ones (→ v17); (b) network RCEs land non-root here
and privesc has **no kernel exploit** in its repertoire (→ v15/v16).

## Phase 4 — flaw-adaptation findings (v13–v15)

Five `flaw_*` graphs (one broken stage each) tested graph adaptation and exposed:

- **v13 / P0 (`185f187`)** — the no-LLM direct path had **no verification**:
  `flaw_impact` wrote to `/root` as a non-root user → "permission denied" yet the
  node reported success ("Executed 3 commands"). Fix: capture session **stderr**
  so the failure scanner detects denied writes / missing files.
- **v14 / P1 (`3d88e92`)** — after escalate failed *non-retryably*, the replanner
  recreated `gain_access→escalate` and re-ran the dead node (~2× 300s). Fix:
  track non-retryably-dead nodes and never re-route to them.
- **v15 / P2 (`6f732e7`)** — `flaw_privesc` confirmed privesc only tried manual
  vectors (cron/suid) and never the kernel path, because the sessions are
  command_shell and `local_exploit_suggester` + overlayfs/dirtycow need
  **meterpreter**. Added upgrade-then-kernel guidance to the PLANNER/EXECUTOR
  prompts. (Left half-wired — finished in v16.)

## Phase 5 — subagent refinement (v16–v19, this batch)

**Privesc kernel path, finished and made end-to-end usable (v16a/b/c).**

- **v16a (`605b7e5`)** — v15's guidance never fired in the **Enumerator**, which
  runs the suggester *first* but was told to skip it on a command_shell (every
  session here). Now the Enumerator upgrades command_shell→meterpreter first, runs
  the suggester, and reports `Meterpreter session:` / `Suggested local exploits:`.
- **v16b (`0120c92`)** — `PrivEscFindings` carried no `session_id`, so a
  rooted/upgraded session was orphaned: `_find_session` always handed impact the
  *original* shell, and (since `gather_preceding_findings` returns direct
  predecessors only) a privesc→impact edge got gated → replanner churn. Now
  privesc propagates the newest **live** escalated session
  (`_resolve_final_session`) and `_find_session` prefers the most-escalated one.
- **v16c (`e287af5`)** — the critic grounded PASS on `id`, but **meterpreter
  rejects `id`** ("Unknown command") — so a genuinely rooted kernel session was
  falsely FAILed, defeating 16a/b. `_direct_priv_check` now probes the
  type-appropriate command (`id` for shell, `getuid` for meterpreter) and the
  grounding rule reads both forms. Still grounded → no false positives.

**initial_access proven-vector bias (v17, `5b1caa9`).** The plumbing existed
(`query_successful_attacks` is called first; banned-module tracking) but the
planner had no rule to *jump* to a proven vector on retry. Now the researcher tags
hits `[PROVEN]` and the planner selects a non-banned `[PROVEN]` vector on
retry/fallback instead of grinding the failed unproven one.

**Credential-retry rotation (v18/v19, from `credential_retry_plan.md`).**
The replanner couldn't retry a credential attack with *different* credentials:
the anti-repeat guard banned a module after one failure, and the tiny-intent had
no creds slot. v18 (`93aabba`, plumbing): `_config_key(module, options)` so the
guard blocks only module+options matches (same module + new creds is allowed);
intents carry `module_options`; failed nodes surface their creds; broadened the
`auth_failed` category regex. v19 (`05530bc`, prompt nudge): on
`failure_category=auth_failed`, rotate creds on the same module before switching
vectors.

---

## Themes (what kept recurring)

1. **Honesty over optimism.** The biggest class of bug was a stage reporting
   success it hadn't verified (v2 prose, v13 direct path, v16c meterpreter). The
   fix was always the same shape: an independent, **grounded** ground-truth check
   the LLM can't talk its way around.
2. **Bound everything.** Unbounded tool calls (v4) and unbounded grinding (v7,
   v12) were the real "slowness." Wall-clock time-boxes + capped attempts +
   category-aware no-retry (v10) keep runs bounded.
3. **Plumbing, not prompts, was usually the gap.** Session propagation (v5, v16b),
   message-window pairing (v6), failure-cause surfacing (v13, v18) — the LLM was
   fine once the data reached it correctly.
4. **Test offline first.** v8+v9 turned 20–40-min live discoveries into 5-second
   unit checks. v16–v19 shipped +29 offline checks (52 total across 8 suites).

## Open — NEED live validation (MS3 kernel 3.13 + Kali)

The v16–v19 batch is offline-tested and committed but **not live-validated**:

1. **privesc kernel path reaches uid=0 end-to-end** (16a/b/c) — the roadmap's
   standing gate. overlayfs (CVE-2015-1328) is the cleaner of the two vectors.
2. **v17 pivots to UnrealIRCd** on continuum/drupal instead of time-boxing.
3. **v19 proposes `ssh_login(vagrant/vagrant)`** after root/root fails — driver
   `experiments/live_test_init_fail.py`.

Lab confounders to clear first (not code): restart `msfrpcd` between runs
(`experiments/restart_msf.py`), flaky UnrealIRCd after heavy use, Kali eth1
dropping. See `refinement_roadmap.md` for the remaining P2/P3 items.
