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
## v5 — (pending)
## v6 — final (pending)
