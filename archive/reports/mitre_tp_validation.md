# MITRE Technique/Procedure Boundary — Live Validation & Bug Tracker

**Living document.** Validating the T/P redesign (replanner picks the MITRE
**technique**, subagent picks the **procedure** under it) against the lab, starting
with the problematic persistence graph and widening to the full suite.

Started **2026-07-15**. Branch `graph-orchestrator`.

**Status:** ☐ open · ◐ in progress · ☑ done
**Type:** `coding-bug` (unintended; bad code → *patch it*) · `design-gap` (bad
outcome from a bad shape → *rethink it*) · `ops` (lab/environmental).

> Working method (CLAUDE.md): classify each bug **logical/coding** vs **design**
> before fixing. Coding → patch + offline-test + commit. Design → note it, discuss,
> don't paper over it. One commit per change.

## What we're validating (the redesign, commits `70b3d1a` → `efb63a3` → `6ae8781`)
- **B1 — subagent honors the assigned technique:** a node with `technique_id` set
  locks the persistence planner to procedures under that ONE technique; it varies
  the *procedure* on retry and emits `TECHNIQUE_EXHAUSTED`/FAILs rather than
  self-switching techniques.
- **B2 — replanner grows the next technique:** on a stuck persistence node, the
  replanner picks the next AVAILABLE menu technique (failed = TRIED, incompatible =
  N/A) and grows a technique-typed node; the subagent then executes its procedure.
- **B3 — Fix 3 still holds:** the subagent's self-proposed VERIFICATION_PLAN
  (proof-of-execution, e.g. a fired heartbeat) is honored.

## Lab config for this validation
VM lab: Kali VM `192.168.34.6` (msfrpcd :55553, reverse handlers on .6), target
MS3 `192.168.34.7`. `LHOST=192.168.34.6`. (The earlier sweep used a *container*
Kali with LHOST=.1; this run uses the VM Kali, self-consistent — a session opened
and RPC auth verified.)

---

## Runs

| # | Graph | Result | B1 | B2 | B3 | Notes |
|---|-------|--------|----|----|----|-------|
| 1 | flaw_persistence | ◐ killed ~22min (harness bg-cap) | ✅ | ⏳ | ⏳ | B1: planner locked to `systemd_service`, no self-switch. Killed before replan. |
| 2 | flaw_persistence | ◐ stuck 60min (V1) | ✅ | ⏳ | ⏳ | Surfaced **V1**: locked systemd ground the full retry budget. Killed, fixed. |
| 3 | flaw_persistence | ◐ (V1 fixed, V2 found) | ✅ | ❌→fix | ⏳ | **V1 fix works live** — `INFEASIBLE … failing fast (TECHNIQUE_EXHAUSTED)` in seconds. Surfaced **V2**: replanner backtracked to gain_access, never grew cron, skipped to file_drop. Fixed (`d21e3e0`). |
| 4 | flaw_persistence | ⏳ running (V1+V2 fixed) | | | | Expect: systemd fast-fail → replanner grows cron → cron self-verify → PASS. |

---

## Findings (code/design bugs found during validation)

### V1 — assigned technique with NO bundled procedure emits placeholder-laden, non-executable steps  `design-gap` · Med · ☐
- **Evidence:** run 1 — `persist` locked to `systemd_service` (T1543.002, no bundled
  procedure in `_get_recommended_techniques` → hint+RAG branch). Planner emitted
  `ACCESS_LEVEL: <current access level>`, `tool_session_command(session_id, ...)`,
  `ExecStart=/path/to/your/script.sh`; executor then ran with the literal string and
  got `Error: Session <current_session_id> not found`.
- **Root cause:** the no-bundled-procedure branch gives the planner only prose + RAG,
  none of it carrying the REAL session id / payload path (the bundled techniques embed
  `{session_id}` via f-string). So the LLM invents unfillable placeholders.
- **Compounding:** systemd is also doomed here (MS3 ub1404 = upstart, no systemd; session
  non-root) — so a locked-to-systemd subagent SHOULD recognise incompatibility and emit
  `TECHNIQUE_EXHAUSTED` fast, rather than grinding placeholder unit-file writes.
- **Fix direction (design):** (a) the no-procedure branch should still inject the real
  session id + a concrete payload example; (b) a locked technique that is
  root-only on a non-root session, or whose tooling is absent, should bail to
  `TECHNIQUE_EXHAUSTED` quickly so the replanner grows a compatible technique. Note,
  discuss — don't paper over.
- **Silver lining:** this is exactly the messy-but-correct failure that should trigger
  B2 (replan systemd→cron). Validating that is the point of the re-run.

**V1 status: ☑ FIXED (`58973ca`)** — deterministic feasibility precheck in
run_persistence fast-fails an infeasible locked technique to
`failure_category=technique_infeasible` before the grind. Confirmed live in run 3
(systemd → fast-fail in seconds).

### V2 — replanner abandons a failed tactic when it backtracks to a predecessor  `design-gap→code` · High · ☑ FIXED (`d21e3e0`)
- **Evidence:** run 3 — persist (systemd) fast-failed; walker backtracked and replanned
  from `gain_access`. Menu/grow_technique were gated on the STUCK node being a
  persistence node, so at gain_access no menu appeared → replanner re-pointed to persist
  (retry) then `NEW EDGE: gain_access → file_drop` (**abandoned persistence**).
- **Root cause:** trigger shape — gated on stuck-node tactic, but the walker replans from
  the PREDECESSOR of a failed node.
- **Fix:** inject the menu / allow grow_technique when a node of the tactic FAILED and the
  tactic is in the objective (not only when stuck AT it); give grow_technique PRECEDENCE
  over skip-connecting to a later READY node; suppress once the tactic is satisfied.

### V2b — mark_failed never stored findings; infeasible technique was retryable  `code` · High · ☑ FIXED (`97b7f57`)
- **Evidence:** run 4 — `node.mark_failed()` only records a reason string, so
  failure_category/method/technique were invisible; the menu couldn't mark systemd
  TRIED and the walker looped `new_edge → persist`.
- **Fix:** walker stores `node.findings = findings` on failure; technique_infeasible/
  technique_exhausted are non-retryable → the fixed-technique node is marked dead →
  replanner grows the next technique. `_failed_techniques` is findings-based.
- **Confirmed live (run 5):** `marked dead` → `GROW TECHNIQUE: persistence_cron_job
  (T1053.003)` → subagent locked to cron. **B2 validated.**

### V3 — DEAD NODES guidance told the replanner to re-exploit instead of trying another technique  `design-gap→code` · Med-High · ☑ FIXED (`b2b6a3f`)
- **Found by the user** reading the raw replan context: with `persist` DEAD, the
  dead_block said "propose use_module with a DIFFERENT exploit against a service"
  (get a new shell) — contradicting the tech_block (grow_technique) and wrong when a
  session already exists and only the technique failed.
- **Fix:** dead_block is now session/technique-aware — technique menu live → steer to
  grow_technique; session but no menu → route to a READY node; no session → keep the
  re-exploit advice. Removes the conflict; makes grow-technique-first robust, not luck.

### V0 (ops) — harness killed the background run ~22 min in
- The `run_in_background` python was killed mid-run (not by me). Switched to a fully
  detached `nohup … & disown` launch (untracked by the harness) so long runs survive.
  Note: monitors on these need re-arming (they time out at their cap while the run
  continues); poll the log directly when a monitor expires.

---

## Log index
_(run logs listed here as they complete)_
