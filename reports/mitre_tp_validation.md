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
| 1 | flaw_persistence | ◐ killed ~22min (harness bg-cap) | ✅ | ⏳ | ⏳ | B1 confirmed: planner locked to `systemd_service`, did NOT self-switch to cron. Killed before replan. Re-running detached. |

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

### V0 (ops) — harness killed the background run ~22 min in
- The `run_in_background` python was killed mid-run (not by me). Switching to a fully
  detached `nohup … & disown` launch (untracked by the harness) so long runs survive.

---

## Log index
_(run logs listed here as they complete)_
