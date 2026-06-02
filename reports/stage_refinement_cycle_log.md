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
**Result (R3):** flawed graph validated the fallback (above). goalonly + success re-run
in progress (runner hardened: survives per-graph timeout, 2400s cap).

## v4 — (pending R3 goalonly findings)
## v5 — (pending)
## v6 — final (pending)
