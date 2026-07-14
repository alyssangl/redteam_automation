# Container-Lab Sweep — Findings & Fix Tracker

**Living document.** Running log of problems found while sweeping the graph suite
against the **container lab** (Kali container + Metasploitable 3 VM) to answer:
*"how many graphs succeed, and where does the architecture actually fail?"*

Started **2026-07-15**. Update as the sweep finishes and as fixes land.

**Status:** ☐ open · ◐ in progress · ☑ done
**Type:** `plumbing` (lab/container config, migration leftovers) · `coding-bug`
(unintended; bad code → *patch it*) · `design-gap` (bad outcome from a bad shape →
*rethink it*) · `ops` (operational/environmental)

> Working method (from CLAUDE.md): classify each bug **logical/coding** vs **design**
> before fixing. Coding → patch. Design → rethink the shape, don't paper over it.

---

## 1. Lab plumbing — ✅ FIXED (migration leftovers, NOT architecture)

The VM→container migration left the reverse-shell path stale. All three fixed &
verified; reverse shells now complete in the container lab for *any* graph (not
just proftpd). Key realization: **the architecture was fine — the plumbing was stale.**

- ☑ **P1 — LHOST hardcoded to dead `.6`** → `os.getenv("LHOST", "192.168.34.1")`.
  22 files, `experiments/live_test_*.py`. Reverse callback now targets the
  host-only adapter (`.1`) the target can actually reach.
- ☑ **P2 — only ports 4444/4445 published** → range **`4444-4480`**.
  `docker-compose.yml` (Kali recreated). Any LPORT the exploit/replanner picks now
  forwards host→container.
- ☑ **P3 — reverse handler can't bind LHOST inside container** → global
  `setg ReverseListenerBindAddress 0.0.0.0` at console init.
  `tools/metasploit_tools.py:__init__`. Verified: `Started reverse TCP handler on
  0.0.0.0:PORT`. (The container doesn't hold `.1`; bind `0.0.0.0`, still advertise
  `LHOST=.1` to the target. proftpd did this per-module; now it's global.)

---

## 2. Pending problems (real findings — the actual answer to "where does it fail")

| ID | Title | Type | Sev | Status | Affected graphs |
|----|-------|------|-----|--------|-----------------|
| F2 | `impact/file_drop` declares success **without grounding** | design-gap | **CRITICAL** | ☑ **FIXED** (unit + offline) | ~every graph reaching impact via command_shell |
| F5 | `command_shell` "(no output)" read-loop starvation | coding-bug | **CRITICAL** | ☑ **FIXED** (verified live) | ~every command_shell run (makes F2 systematic) |
| F1 | Handler-job leak → listener-port collision | coding-bug | **High** | ☑ **FIXED** (verified live) | flaw_initial_access, goal_only, flawed |
| F3 | No session-liveness gate before post-exploitation | design-gap | Med-High | ☐ | privesc / persistence / impact |
| F4 | Session-id mismatch (looked for `1`, session was `2`) | coding-bug | Med | ☐ *needs investigation* | flaw_privesc (+?) |
| F6 | privesc runs **attacker-side** cmds in target shell | design-gap | Med | ☐ | privesc |
| F7 | recon conflates `SSH_TIMEOUT` with "no open ports" | design-gap | Low-Med | ☐ | recon under lab degradation |
| F8 | replanner weak recovery on non-retryable node fail | design-gap | Low | ☐ *moot if F1 fixed* | flaw_initial_access |
| F9 | **target clock drifted to Feb 9** (breaks time-based verify) | ops | Low-Med | ☐ | any time/log correlation |

> ⚠️ **METRIC TRUST WARNING.** The pipeline's raw `Success rate: %` is **NOT trustworthy for the
> impact node** — F2×F5 make `command_shell` impact/file_drop declare success blindly. Every
> reported % must be **re-scored by grounding** (read the artifact back from the target — e.g.
> `curl http://TARGET/pwned_*.txt`) before it counts. `recon` and `initial-access` successes ARE
> grounded (real nmap output / real `Session N opened`) and can be trusted.
>
> **Confirmed:** proftpd's own "80% baseline" — its file_drop logged `success` while the read-back
> `cat` returned `(no output)`. Out-of-band `curl` proved the file *does* exist (capability real),
> but the pipeline **never verified it** — ungrounded success, systematic on command_shell.

### F1 — Handler-job leak → listener-port collision  `coding-bug` · High
- **Evidence:** `logs/flaw_initial_access_..._174147.log:76` —
  `proftpd_modcopy_exec - binding issues on listener port`; checkpoint showed
  `Handler failed to bind to 0.0.0.0:4444` (port already in use).
- **Root cause:** the exploit subagent does **not** kill/rotate the reverse-handler
  job between retry attempts. A leaked handler from a failed attempt holds the port,
  so even the **correct** next exploit can't bind its listener → no session.
- **Why it matters:** the subagent chose the *right* vector (`proftpd_modcopy`, the
  proven 80% exploit) and was blocked purely by this. The *intelligence* worked; the
  *mechanics* failed. Actively suppresses recovery on improvisation-heavy graphs.
- **Fix:** before each new exploit attempt, `jobs -K` the prior handler (or bump
  LPORT). Localized to the exploit subagent / execution path.
- **Verdict:** coding bug, **not** an architecture rework.

### F2 — `impact/file_drop` declares success WITHOUT grounding  `design-gap` · **CRITICAL**
- **Root cause:** impact/`file_drop` counts commands **sent**, not commands that
  **succeeded** — no grounding check that the read-back output is real.
- **SYSTEMATIC, not rare** (corrected — first calibration was wrong). On a
  `command_shell` session (most MS3 Linux exploits), the write cmds have no output AND
  the read-back is eaten by **F5** → the stage can never ground → declares success
  anyway. Two flavors:
  - *Ungrounded (common):* live session, read-back eaten → success on luck.
    **Confirmed in proftpd's own 80% baseline:** `cat pwned_proftpd.txt` → `(no output)`,
    yet `STATUS → success: Executed 4 command(s)`. Out-of-band `curl` proved the file
    *does* exist — capability real, but the pipeline **never verified it**.
  - *Outright false:* dead session, every cmd `Session not found`, still "success"
    (`flaw_privesc`, reported 75% / true ~50%).
- **Why it matters:** the reported `Success rate` is inflated by ~1 node (impact) on
  every command_shell graph. Violates "grounding beats prose / mandatory FAIL when
  unverified."
- **Fix:** treat `Session … not found` / `(no output)` on a read-back as **FAIL**;
  require the artifact to actually read back (needs **F5** fixed first, else the
  read-back can't return content). Depends on F5.

### F3 — No session-liveness gate before post-exploitation  `design-gap` · Med-High
- **Evidence:** `flaw_privesc` — `escalate` ran on a session that had died
  (`SESSION LOST`), then `file_drop` ran on dead session 2.
- **Root cause:** privesc/persistence/impact don't verify the session is alive before
  acting → confusing `Session not found` cascades three stages deep.
- **Fix:** liveness probe (`id`/`getuid`) before each post-exploitation stage; fail
  honestly if dead (re-exploit or abort). *(Flagged as a proposed fix in an earlier
  session.)*

### F4 — Session-id mismatch  `coding-bug` · Med · needs investigation
- **Evidence:** `flaw_privesc` — `gain_access` opened **Session 2**; `escalate`
  failed with `Error: Session 1 not found`.
- **Root cause:** TBD — trace how `session_id` flows `gain_access → escalate`. Either
  a wrong/stale id reference or the session died and a stale `1` was used.

### F5 — `command_shell` "(no output)" read-loop starvation  `coding-bug` · **CRITICAL**
- **Evidence:** `tools/metasploit_tools.py:~103` `run_session_command`, command_shell
  branch **breaks on the first empty read** (`if not data: break`) — the inverse of the
  meterpreter branch (`if data: break`, which waits for output to appear). proftpd
  file_drop: every `cat` read-back returned `(no output)` despite the file existing.
- **Why CRITICAL:** this is the **enabler of F2** — it eats the read-back output on
  command_shell, so impact/file_drop can *never* verify, which is why F2 is systematic.
  Fix this first; it unblocks all grounding on command_shell sessions.
- **Fix:** mirror the meterpreter branch (keep reading until output arrives or timeout).
  Small, localized. *(Carried over from an earlier session — now upgraded.)*

### F6 — privesc runs attacker-side commands in target shell  `design-gap` · Med
- **Evidence:** earlier proftpd run — privesc ran `msfvenom`/`chmod` a payload inside
  a `www-data` **target** shell (nonsensical there).
- **Fix:** constrain privesc to target-appropriate enumeration/exploitation; no
  attacker-side tooling inside the target session. *(Carried over.)*

### F7 — recon conflates `SSH_TIMEOUT` with "no open ports"  `design-gap` · Low-Med
- **Evidence:** `init_fail` logs — nmap `SSH_TIMEOUT` surfaced as "No open ports
  discovered"; judge then adapted with "try alternative scan options" (useless remedy
  for an infra timeout).
- **Fix:** surface `SSH_TIMEOUT` as an **infra** failure, not a scan-strategy problem.

### F8 — replanner weak recovery on non-retryable node failure  `design-gap` · Low
- **Evidence:** `flaw_initial_access` — when `gain_access` failed non-retryably, the
  replanner only re-pointed a new edge at the **dead** node (rejected) instead of
  synthesizing a new exploit node from recon data.
- **Note:** **moot if F1 is fixed** — with handler hygiene fixed, the subagent
  recovers *inside* `gain_access` (via ProFTPD) and never reaches the replanner.
  Keep as a lower-priority robustness observation.

### F9 — target (MS3 VM) clock drifted to Feb 9  `ops` · Low-Med
- **Evidence:** Apache `Date:` header from the target = `Mon, 09 Feb 2026`; the proof
  file's `Last-Modified` matches. MS3 VMs freeze their clock on save/restore.
- **Why it matters:** breaks any **time-based** verification, log↔target correlation,
  or freshness check (e.g. "was this file written *this* run?" is unanswerable by
  timestamp). Also skews `$(date)` inside dropped proof files.
- **Fix (ops):** sync the VM clock on boot (`ntpdate`/`hwclock`), or use a unique
  per-run **content marker** (not a timestamp) to prove freshness.

---

## 3. Sweep results (running tally — container lab, post-plumbing-fix)

> ⚠️ Raw `%` below is the **pipeline's self-report** — inflated on the impact node by
> F2×F5. Treat impact/persistence success as **UNVERIFIED** until re-grounded.

| # | Graph | Result | Note |
|---|-------|--------|------|
| — | proftpd_modcopy (baseline) | **80%** | happy path; session survived to file_drop |
| 1 | flaw_recon | **100%** | replanner rerouted to UnrealIRCd ✅ |
| 2 | flaw_initial_access | **25%** | blocked by **F1** (subagent chose right, couldn't bind) |
| 3 | flaw_privesc | *(pre-fix run showed F2/F3/F4)* | re-run pending |
| 4 | flaw_persistence | TBD | |
| 5 | flaw_impact | TBD | |
| 6 | init_fail | TBD | replanner recovery test |
| 7 | flawed | TBD | |
| 8 | goal_only | TBD | auto-mode; likely hits F1 |
| 9 | samba | TBD | scenario (first-try; F1 shouldn't bite) |
| 10 | unrealircd | TBD | scenario |
| 11 | drupal | TBD | scenario |
| 12 | elasticsearch | TBD | scenario |
| 13 | jenkins | TBD | scenario |
| 14 | continuum | TBD | scenario |

---

## 4. Ops / environmental notes (not code — but they wreck runs)

- ☑ **Host sleep kills live runs.** Windows sleep freezes the VM+containers and
  **kills live reverse-shell TCP sessions**; on resume, post-exploitation inherits a
  dead session. Disable AC sleep for the duration of a run. *(Confirmed 2026-07-09.)*
- ☑ **Stale Kali container degrades nmap-over-SSH.** A container up ~5 days made even
  3-port scans `SSH_TIMEOUT`; a fresh restart fixed it. Sweep runner now restarts Kali
  only on the `SSH_TIMEOUT` symptom.
- **Cold start after time away:** Docker Desktop *and* the MS3 VM are both off — start
  both (`docker compose up -d kali`, `VBoxManage startvm Metasploitable3-ub1404
  --type headless`).

---

## 5. Next steps

1. Let the current sweep finish all 14 → fill in §3.
2. Fan out analysis subagents over the logs → confirm/classify each failure AND
   **re-ground every impact success** out-of-band (read the artifact back from the
   target, e.g. `curl http://TARGET/pwned_*.txt`) so §3 shows *verified* %, not the
   pipeline's self-report.
3. **Fix order (revised — metric integrity first):**
   - **F5** (read-loop) — enables grounding on command_shell. *Do first.*
   - **F2** (impact must verify read-back, else FAIL) — depends on F5.
   - **F1** (handler-job hygiene) — unblocks correct recovery on retry-heavy graphs.
   - **F3** (session-liveness gate) — stops the dead-session cascades.
   - Then F4 / F6 / F7 / F9.
4. Re-run the affected graphs on the fixed lab: flaw_privesc (F2/F3/F4), the
   improvisation-heavy ones (flaw_initial_access, goal_only, flawed) for F1, and a
   command_shell impact graph to confirm F5/F2 now ground.

---

## 6. Overnight autonomous run — 2026-07-15 night

Loop: run graph → **fully read log** → classify new bugs (code/design + importance)
→ **re-ground** impact successes out-of-band (curl the artifact) → fix **critical/high
CODE** bugs immediately (stop loop, commit, verify); **medium CODE** bugs after the
full run; **design bugs + low bugs left for discussion**. F1/F2/F5 fixed pre-run.

### Verified pass tally (grounded, not pipeline self-report)
| # | Graph | Pipeline % | Verified | Note |
|---|-------|-----------|----------|------|
| 1 | flaw_recon | 75% | re-run pending | recon✓ replan→UnrealIRCd✓ gain_access✓; file_drop false-FAILED on the F5b bug (file WAS written) → re-running after fix |

### New findings this run (F10+)
- **F5b** · `code` · **HIGH** · ☑ FIXED — the F5 bounded-wait was incomplete: UnrealIRCd
  `reverse_perl` command_shell buffers a command's output until the NEXT write, so `cat`
  read-backs returned `(no output)` and F2 **false-NEGATIVED a real write** (flaw_recon
  file_drop failed though `PWNED…User: boba_fett` was written, visible one read later).
  Fixed with a marker-based read (write command + unique end-marker echo; read until the
  marker, return everything before it). Verified live on reverse_perl + offline suite.
- **F11** · `code` · **MED** — impact subagent's session-liveness check runs a malformed
  `sessions` command (`Wrong number of arguments expected: 1, received: 0`) and concludes
  a *live* session is dead → skips impact. Fix after full run.
- **F12** · `design` · **MED** — F2's positive grounding only covers nodes that declare a
  `marker`; no-marker impact/enum nodes (e.g. replanner-grown `passwd`) still pass on
  `(no output)` (false success). For discussion — largely mooted once F5b makes output real.

---

## Nemotron migration (parallel track — paused)

Self-hosted Nemotron-3-super vLLM on `gx10-e36e.tail12cca0.ts.net` (Tailscale
`100.86.72.15:8000`, OpenAI-compatible). Client side ready (env-flagged `base_url`
factory, OpenAI stays fallback). **Blocked on:** server needs relaunch with
`--enable-auto-tool-choice --tool-call-parser qwen3coder --reasoning-parser
nemotron_v3` (verified parser names for this vLLM 0.21 build). Shared/idle box;
coordinate before restart.
