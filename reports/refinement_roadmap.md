# Refinement Roadmap (post-v7)

State at v7 (`7563ad4`): pipeline runs end-to-end, crash-free, bounded (no hangs),
honest (grounded verification), with direct→subagent fallback and a privesc
time-box. Stages refined v1–v6; escalate time-boxed in v7. Remaining work is
**improvements, not fixes** — nothing below is blocking.

Priority key: P1 = highest leverage. Effort/Risk: L/M/H.

---

## Progress (autonomous, post-v7) — all pushed, offline-tested, NEED live validation
- **v8 `d0c50ef` — lazy MSF connection.** Imports no longer connect to msfrpcd
  (verified `connected_at_import=False`); decouples import from the lab, unblocks
  offline tests. ⚠️ live-validate the proxy forwards correctly under real use.
- **v9 `716aeb7` — offline test suite** (`tests/run_offline.py`, 12→18 checks):
  pair-safe, graph shapes, lazy-MSF, retry-policy. Also fixed full-port-scan
  recon hints (`-p 0-65535` → `--top-ports 1000`) in 10 graphs.
- **v10 `63dbad2` — category-aware retry seed** (`_is_retryable_failure`): deterministic
  failures (time-boxed escalate, FAIL_EXHAUSTED) short-circuit to replan instead
  of burning identical retries. ⚠️ live-validate.
- Done earlier: P3 escalate time-box (v7 `7563ad4`), escalate max_retries=1 (`acd66b6`).

**Next:** live-validate v8+v10 (one goalonly/proftpd run) BEFORE more core edits.
Then remaining items below.

---

## P1 — Category-aware retry policy  (effort M, risk M)
**Problem:** node retries fire blindly on `max_retries` regardless of *why* the
node failed. Identical-param retries of a deterministic failure are pure waste
(escalate time-boxed 3×; flawed re-ran the same wrong module 4×).
**Principle:** a retry is only meaningful if (a) the failure was transient/
state-dependent, or (b) the retry *changes an input*. Never retry deterministic/
exhausted failures.
**Plan:** make the judge/orchestrator retry decision read `failure_category`:
- transient (`timeout`, `session_lost`, `connection`) → retry (bounded, maybe
  re-establish the session first)
- param-fixable (`incompatible_payload`, `wrong_targeturi`, wrong port) → retry
  ONLY with a changed param (drive from `module_options_alternatives` / hints)
- deterministic/exhausted (`FAIL_EXHAUSTED`, `timeout`/time-boxed escalate,
  `no-target`) → do NOT retry; mark node failed, let the walker move on
This subsumes the interim graph-level `escalate max_retries=1`.
Files: `core_agents/orchestrator.py` (retry/judge decision), uses existing
`failure_category` keys already emitted by the stages.

## P1 — Offline unit tests for plumbing  (effort M, risk L)
**Why:** almost every bug this project hit was a logic/plumbing bug found only
after a 20–40 min live run. A 5-sec unit test catches them (see the
`_make_pair_safe` test that proved the v6 fix).
**Plan:** a `tests/` dir with pure-logic tests (no MSF/SSH):
- `_make_pair_safe` (parallel tool_calls, orphan tool msgs, plain convo)
- session-guard / `_resolve_live_session_id`
- loop-cap / recursion-budget math per stage
- recon planner port-guard (rejects `-p-`)
- pair-safe windows in persistence
Run them in CI / pre-commit. This is the biggest iteration-speed win.

## P1 — Lab-hygiene automation  (effort L, risk L)
**Why:** the #1 confounder of generalization runs was MSF stale-handler state +
flaky UnrealIRCd after heavy use — not code.
**Plan:** a helper that, before each run, (a) restarts `msfrpcd` on Kali (clears
stale jobs/sessions/handlers), and optionally (b) snapshot-restores the target
VM. The robust runner already restarts/waits; fold msfrpcd-restart into its
`wait_ready`.

## P2 — Privesc kernel local-exploits  (effort M, risk M)
**Why:** on this MS3 (kernel 3.13) the *only* reliable root path is a kernel
local-exploit; the network-service RCEs all land as `www-data`/`boba_fett`.
escalate currently tries sudo→SUID→docker and time-boxes without root.
**Plan:** add to the privesc repertoire/prompts: run `post/multi/recon/
local_exploit_suggester` first, then attempt **overlayfs (CVE-2015-1328)** and
**DirtyCOW (CVE-2016-5195)**. Needs its own live test to confirm it reaches
uid=0. (overlayfs is the cleaner/safer of the two.)

## P2 — Replanner precondition checks  (effort M, risk M)
**Problem:** replanner emitted `recon → persist` claiming "preconditions met"
when no session existed (caught harmlessly by the persist no-session guard).
**Plan:** before the replanner emits an edge into a session-dependent stage
(privesc/persistence/impact/discovery), verify an active session exists in
preceding findings; otherwise route to an access stage first.

## P2 — Credential-retry rotation  (effort L, risk L)
Re-trying the same creds/wordlist is meaningless. Ensure credential attacks
rotate creds/wordlists on retry, never repeat. (See `credential_retry_plan.md`.)

## P3 — Hard escalate time-box  (effort L, risk L)
The v7 time-box is "soft" — it checks between stream steps, so a long in-flight
step overshot 300s→451s. If a hard bound is wanted, run the stream in a thread
with a wall-clock join, or shrink per-call timeouts so steps are smaller.

## P3 — More targets / true Jenkins  (effort L, risk L)
This is the Linux MS3 (no Jenkins; Apache Continuum on 8080). For a real Jenkins
vector use the **Windows MS3** VM. Current generalization graphs:
proftpd, unrealircd, samba, continuum, drupal (real services here) + jenkins
(fallback-only on this box).

---

## Suggested order for a fresh session
1. Offline unit tests (P1) — makes everything after this fast + safe.
2. Lab-hygiene automation (P1) — removes the run confounders.
3. Category-aware retry policy (P1) — kills wasted cycles, subsumes no-retry-on-timeout.
4. Privesc kernel exploits (P2) — first stage that actually reaches root here.
5. Replanner preconditions + credential rotation (P2).
