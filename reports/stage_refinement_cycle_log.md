# Stage-Refinement Dev-Loop Log

Loop: run an example → diagnose what each stage did badly → fan out one worker
per stage to refine (tight kill-chain scope, broad tools/prompts) → commit the
version → re-test. Target: v1…v6, stop after R6.

Test set per cycle (live, against Metasploitable 3 via Kali):
- **goalonly** — every node goal-only → forces all 5 subagents (the real test).
- **success** — hardcoded graph → recon subagent + no-LLM direct path (regression).
- **flawed** — wrong module + dropped privesc → validates direct→subagent fallback (run when fallback logic changes).

Architecture note: a node with a `module`/`commands_to_run` runs the **no-LLM
direct path**; only goal-only nodes (and, since `e0e350a`, *failed* direct nodes
in explore mode) reach the stage subagent. So the goalonly/flawed graphs are
what actually exercise exploit/privesc/persistence/impact subagents.

---

## Run-by-run outcomes — ALL stages
Legend: ✅ success · ❌ fail · ⛔ hung · ⏱ timed out · — not reached · (D) no-LLM direct path · (S) stage subagent

| Run (ver, graph) | recon | initial-access / exploit | privesc | persistence | impact |
|---|---|---|---|---|---|
| R0 v0 success | ⛔(S) recursion_limit ×3 | — | — | — | — |
| R1 v1 success | ✅(S) 12 ports | ✅(D) ssh_login sess1 | ✅(D) sudo verify | ✅(D) ssh-key + cron | ✅(D) file_drop |
| R1 v1 proftpd | ✅(S) 9 ports | ✅(D) modcopy sess2 | ✅(D) enum | n/a | ✅(D) file_drop |
| R2 v2 success | ✅(S) | ✅(D) ssh_login sess3 | ✅(D) | ✅(D) ssh-key + cron | ✅(D) |
| R2 v2 proftpd | ✅(S) | ✅(D) modcopy | ✅(D) | n/a | ✅(D) |
| v2 goalonly | ✅(S) | ✅(S) UnrealIRCd sess5 | ❌(S) "session no longer active" ×3 | ⏱(S) | — |
| R3 v3 flawed | ✅(S) | ✅(S, **fallback**) wrong-module→UnrealIRCd sess1 | (privesc dropped) | ⏱(S) | — |
| R3 v3 goalonly | ✅(S) | ⛔(S) hung on proftpd_modcopy (unbounded MSF call) | — | — | — |

Reading it: success/proftpd graphs only exercise recon as a subagent — the rest is
the no-LLM direct path. The goalonly/flawed graphs are where exploit/privesc/
persistence/impact run as subagents — and that's where the real defects show
(unstable session in v2; the unbounded-MSF hang in v3 → fixed in v4).

---

## v0 — baseline (R0)
**Found:** recon never converged — planner↔executor↔critic looped to LangGraph
`recursion_limit=50` on all 3 retries (full `-p-` nmap scans timing out). Pipeline
died in recon, never reached downstream stages.
**Fix target:** recon convergence/robustness.

## v1 — convergence + contract-safe robustness (commit `9b94626`)
- **recon:** catch `GraphRecursionError`; top-ports-first scans (no `-p-` in phase 1);
  SSH timeout handling; critic hard-cap that emits partial findings; always return findings.
- **initial_access:** act on `failure_category` (switch payload on incompatible, adjust
  TARGETURI) instead of blind repeats; anti-repeat guard; `FAIL_EXHAUSTED` verdict so
  giving-up ≠ success.
- **privesc:** passwordless-sudo fast-path; bounded tool-count loops; tighter critic; capabilities enum.
- **persistence:** session-type-aware techniques; correct datastore option names; anti-repeat.
- **impact:** action verification + bounded executor loop.
**Result (R1):** both graphs ran the FULL chain end-to-end. recon fixed. ✅

## v2 — false-success guards + grounded verification (commit `54d42aa`)
- **recon:** cross-cycle command memory; early-terminate on repeated timeouts; `RECON_SSH_TIMEOUT=120`; tighter partial-success guard.
- **initial_access:** run `id` INSIDE the session (not the Kali console) for access_level; back-fill session_user_info; scoped failure classification.
- **privesc:** attach raw tool outputs as grounded evidence so the critic can't be fooled by prose; regex sudo fast-path; fixed FAIL_ENUM retry counting; forced whoami verification.
- **persistence:** mandatory FAIL when verification empty; real pubkey (no literal placeholder); 3-point cron verification.
- **impact:** action verification.
**Result (R2):** both graphs full-chain again. ✅
**Found (via first goalonly run on v2):** exploit subagent works but landed an
UNSTABLE session (UnrealIRCd backdoor) that DIED before privesc → privesc aborted
"session no longer active". → drives v3.

## (architecture) direct→subagent fallback + flawed graph (commit `e0e350a`)
**Found:** exploit/privesc/persistence/impact subagents were nearly dead code —
every non-recon node (hand-authored or replanner-made) carries a module/commands →
direct path; direct FAILURE just returned, never fell back to the subagent.
**Fix:** in explore mode, a failed direct node now hands off to its stage subagent
to improvise within scope before the walker/replanner. Added `flawed_graph` to test it.
**Result (R3 flawed):** fallback VALIDATED — gain_access failed on closed Jenkins:8484
→ exploit subagent improvised → session via UnrealIRCd. ✅

## v3 — fit stage failure: session-loss recovery (commit `78fad34`)
- **initial_access:** liveness-probe a session before declaring success (dead session ⇒
  honest FAIL, fixes the v2 unstable-session phantom PASS); anti-repeat keyed on
  (module, TARGETURI) so it sweeps URIs instead of giving up.
- **privesc / persistence:** instant `session.list` RPC health check (was a 60s console
  call); on dead session, search session.list for a live substitute on the target and
  SWAP to it instead of aborting; dead-session prompt guidance.
- **recon:** record failed/timed-out commands in anti-repeat memory; early-terminate on
  SSH errors; planner → gpt-4o.
- **impact:** failure-path hardening.
**Result (R3):** flawed graph validated the fallback (above). goalonly **HUNG** —
the exploit subagent fired a Metasploit module (proftpd_modcopy_exec) and blocked
indefinitely with no timeout; 12+ min of zero output before it was killed. The
success regression never ran.
**Found (critical):** stage MSF tool calls (console/RPC/session commands) are
UNBOUNDED — one blocking module hangs the entire run. This is the main cause of
the "why is it so slow" symptom: not thoroughness, an unbounded tool call.

## v4 — bound every tool call (no hangs) + cap attempts  [in progress]
Target: every MSF console/RPC/session command gets a wall-clock timeout and
returns a failure string on timeout (never blocks); cap the number of
exploit/technique attempts so a stage can't run for tens of minutes; keep v3
failure-recovery. Goal: bounded, fast, non-hanging runs.
**Result (R4):** recon now finds port 6667 (top-1000 + non-standard ports);
gain_access succeeded in BOUNDED time (no 18-min hang — the v4 SSH/MSF timeouts
hold). BUT a **regression**: the privesc subagent now crashes every attempt with
OpenAI 400 "messages with role 'tool' must be a response to a preceding message
with 'tool_calls'" — v4's large privesc refactor (SESSION_DEAD mode + capping)
broke the message-window ordering. It fails fast (~25s) and caps at 4 retries
(bounding works) but cannot escalate. → v5 #1 fix.

**Result (R4) — full verdict:** NO HANGS — recon 67s, gain_access 84s, the whole
run completed (was a 12-min freeze in R3). Bounding works.
- recon ✅ now finds 6667/irc (top-1000 + non-standard ports)
- gain_access ✅ session 2 (UnrealIRCd), bounded 84s
- escalate ❌ privesc message-window crash (400 tool/tool_calls) ×4 — REGRESSION from v4
- persist ✅ "Persistence established via cron_job. Verified working."
- impact ❌ "no session available" — session not propagated after escalate crashed
- proftpd_modcopy_exec (replanner-inserted) ✅ via direct→subagent FALLBACK (session 3)
- success regression ✅
Wins: hangs gone; fallback works on replanner nodes; persistence subagent works.

## v5 — fix v4 regression (privesc message-window) + session propagation  [in progress]
Target: repair the privesc 'tool'/'tool_calls' message ordering crash; make all
stages' message-window logic pair-safe; impact falls back to newest live session
on target; keep all v4 bounding.

## v6 — id-aware pair-safe (privesc) + recursion headroom (commit `af0d816`)
- privesc: rewrote `_make_pair_safe` to be id-aware/atomic — an assistant
  tool_calls message is kept only if EVERY tool_call_id has a matching ToolMessage
  in the following run, else the whole group is dropped (fixes the v4/v5 parallel
  tool-call 400 crash in both directions; proven on unit cases).
- recursion_limit headroom for the bounded ReAct sub-loops: persistence 100→250
  (R5 hit 100), privesc 120→200, impact 80→150.
**Result (R6):** privesc CRASH ELIMINATED — 0 occurrences of "did not have
response" / "PrivEsc crashed" / "Recursion limit" across the goalonly run. recon
✅, gain_access ✅ (session 7), success regression ✅. escalate now runs honestly
(grounded id-checks, no false root, no crash) but EXHAUSTS privesc vectors against
a non-root user (boba_fett) — goalonly hit the 40-min runner cap doing thorough
(bounded) privesc. Not a hang/crash; a thoroughness-vs-speed tuning item
(time-box escalate). persist recursion fix validated via the generalization batch.

## Post-v6 generalization batch (flawed + proftpd + jenkins)
flawed: recon→gain_access→persist→impact (privesc dropped) — validates persist/
impact subagents + the recursion fix + fallback. proftpd (21/80 open): should work
directly. jenkins (8484 closed): prescribed exploit fails → fallback improvises.

### Net arc v0→v6
v0 recon crash-loops → v1 works end-to-end → v2 honest (grounded, no false success)
→ v3 resilient (session recovery) + direct→subagent fallback → v4 bounded (no hangs)
→ v5 partial pair-safe → v6 id-aware pair-safe (crash gone) + recursion headroom.
Open tuning item: time-box escalate so exhaustive privesc doesn't blow the clock.

## v7 — escalate time-box (commit `7563ad4`) + escalate max_retries=1 (`acd66b6`)
PRIVESC_WALLCLOCK_TIMEOUT=300s (soft — checks between stream steps, overshoots
~450s). max_retries=1 on the goal-only escalate node (a deterministic timeout is
not worth retrying — interim until category-aware retry, roadmap P1).

## Generalization examples (v7) — full chain on real MS3 services
Privesc node converted enum-only `privesc_lookup` → goal-only `escalate` (`d15a048`)
so it invokes run_privesc. Edge gating note: file_drop ends up gated behind a live
session, recovered by the replanner when escalate kills the session.

| Graph | Result |
|---|---|
| **proftpd** (R-v9) | **COMPLETE 83%** — proftpd_modcopy (own vector), escalate✗, file_drop✓ (replanner-recovered session). |
| **unrealircd** (v11) | **COMPLETE 80%** — irc_backdoor (own vector) session 1, escalate✗, file_drop✓. |
| **samba** (v11) | **COMPLETE 80%** — is_known_pipename DIDN'T land → fallback improvised to UnrealIRCd (session 2), escalate✗, file_drop✓. Demonstrates fallback resilience, not a Samba compromise. |
| **continuum** (v11) | **TIMEOUT (40m cap)** — apache_continuum_cmd_exec didn't land; fallback ground through options without converging. |
| **drupal** (v11) | **TIMEOUT (40m cap)** — drupalgeddon2 didn't land; fallback ground without converging. |

v11 ALSO live-validated v8 (lazy MSF connects on first use, not import) + v10 (escalate
one-attempt: "failed (non-retryable / deterministic)" — no 3× grind).

NEW FINDING (→ roadmap P1): continuum/drupal timed out because the EXPLOIT subagent
(run_exploitation) has NO wall-clock time-box (privesc got one in v7). When the
prescribed vector fails it grinds for 40 min instead of bounding the attempt and
letting the walker pivot to a known-good vector. Fix = mirror v7's time-box in
run_exploitation. Secondary: the fallback/replanner should prioritize a PROVEN
vector (UnrealIRCd here) over grinding unproven ones.

KEY FINDING (→ roadmap): on this box network RCEs land non-root (www-data/boba_fett)
and there is no kernel-exploit in privesc's repertoire, so escalate honestly fails —
expected. AND the slow escalate can KILL the command_shell session before impact,
forcing a replanner re-exploit. Both point to: (a) privesc kernel local-exploits,
(b) bound escalate tighter / don't let privesc destroy the session, (c) gate impact
on "session exists" with a re-establish path.
