# GRAFT — smoke-test results (T1–T7)

The 7 gate tests from `experiment_plan.md §4` — the bar the
campaign had to clear before any recovery/grounding number counted. All run on the
isolated lab: Metasploitable 3 target (192.168.34.7), Kali attacker + msfrpcd
(192.168.34.6), GPT-4o judge/replanner._

## Bottom line

**All 7 pass.** The gate is cleared, so the N=10 campaign that followed rests on a
verified foundation. Two of the seven caught **real defects** before the campaign
ran (T7 a scoring bug, T6 a read-reliability failure) — which is the point of a
smoke gate: find the invalidating problem in a 5-second check, not in a 40-minute
run whose data you then can't trust.

| # | What it gates | Kind | Result |
|---|---|---|---|
| T1 | A clean, no-fault run actually grounds its objective | live | ✅ PASS |
| T2 | Capability loss fires the feasibility gate → graft | live | ✅ PASS |
| T3 | The NO-GRAFT ablation truly disables the graft | live | ✅ PASS |
| T4 | Grounding cannot be spoofed by the agent's own text | offline | ✅ PASS |
| T5 | Repair is budget-bounded (no runaway graph growth) | offline + empirical | ✅ PASS |
| T6 | A re-provisioned session's reads return real output | live | ✅ PASS (fixed a bug) |
| T7 | Capability loss never blacklists a good technique | live + offline | ✅ PASS (fixed a bug) |

---

## T1 — No-fault sanity: a clean run grounds its objective

**Proves.** Before testing *recovery*, prove the system can succeed at all and that
"success" means something. A full run with **no fault injected** must reach the
objective and have it grounded, with no false success.

**How.** `examples/baseline_impact_graph.py` — the normal chain `recon →
gain_access → file_drop`, **no** session kill — run live as `v0_full`.

**Result — ✅ PASS.** `completed=True`, `grounded_success=True` (proof marker
written *and read back* off the target), `false_success=False`, **0 grafts**, 0
replan edits. The negative control for the whole study: the baseline grounds cleanly
and grows nothing, so every recovery number afterward is measured against a
trustworthy zero.

---

## T2 — Capability loss fires the feasibility gate (the core of the graft)

**Proves.** When a held capability is destroyed, the system must **detect** it
(feasibility gate `F=0`), **classify** it as a capability loss (the missing
capability was ever-held, i.e. in the history `H`) rather than a technique failure,
and route to the graft — exactly once, with no loop.

**How.** `orphan_c` run live: `recon → gain_access` (session 1 opens) → the harness
kills session 1 before `file_drop` → observe the `[F]` diagnostic line and the graft.

**Result — ✅ PASS.** The live logs show the full sequence:
```
[F] file_drop: required={session} world={} sessions(id,alive)=[('1', False)]  → category=capability (κ ∈ H)
[Replanner] grow re_exploit ; re-attach + revive file_drop onto it
[F] file_drop: required={session} world={session} sessions=[('1',False),('2',True)]  → PASS
```
`F=0` fires **once**, **one** graft, no loop; `file_drop` then executes on the fresh
session 2. This is capability orphaning + structural repair working on a real target.

---

## T3 — The NO-GRAFT ablation truly disables the graft

**Proves.** The FULL-vs-NO-GRAFT contrast is only meaningful if NO-GRAFT actually
removes the graft (and nothing else). NO-GRAFT must grow **zero** grafts on the same
capability-loss break.

**How.** `orphan_c` run live as `v_nograft` (`EVAL_ENABLE_GRAFT=0`).

**Result — ✅ PASS.** **0 grafts, 0 recovery** across every NO-GRAFT run. The
capability failure routes to the ordinary technique-substitute path, which cannot
restore a lost session — so recovery collapses. This is the mechanism behind the
headline 8/10-vs-0/10: the zero is by construction, not by luck.

---

## T4 — Grounding cannot be spoofed by the agent's own text

**Proves.** The oracle must reject a success "proven" only in the agent's prose. A
fabricated `uid=0(root)` or proof marker sitting in the model's output must **not**
ground; only a token captured off the target may.

**How.** Offline adversarial unit test `tests/test_t4_grounding_not_spoofable.py`
(5 checks): feed grounding a finding whose *prose* contains `uid=0(root)` / the
marker but whose *captured output* does not.

**Result — ✅ PASS.** Both privesc and impact grounding return **False** on
prose-only tokens, and **True** only when the token rides on captured target bytes
(a `DIRECT ID CHECK` line, a `cat` read-back). This is `Δ_A = 0` demonstrated at the
oracle boundary — the property is a code invariant, not a run outcome.

---

## T5 — Repair is budget-bounded (no runaway growth)

**Proves.** The replanner/graft must not grow the graph without bound. With repair
budget `B`, the number of grown nodes must satisfy `grown ≤ B`, and an exhausted (or
zero) budget must **abandon** cleanly — no LLM call, no grown node.

**How.** Offline unit test `tests/test_t5_budget_bound.py` (3 checks) for the
`B=0` / exhausted paths, plus an empirical check across the live orphan runs.

**Result — ✅ PASS.** `B=0` and exhausted budget both ABANDON with no growth; the
loop invariant `grown ≤ B` holds. Empirically **0 of 14** orphan runs exceeded
`|V₀| + B` (observed max grown = 1, with `B = 10`). Termination is guaranteed, not
hoped for.

---

## T6 — A re-provisioned session's reads return real output

**Proves.** The graft is pointless if the fresh session it provisions can't be read.
After a re-exploit, a read command (`cat`, `id`) must return **actual output**, not
an empty string — otherwise the revived objective silently fails to ground.

**How.** Live diagnostic (`scratchpad/diag_t6.py`): issue 20 reads on the
re-provisioned session, comparing a raw `command_shell` against a
**meterpreter-upgraded** session.

**Result — ✅ PASS — and it caught a real bug.** The raw re-provisioned
`command_shell` is a **read-zombie**: it returns `(no output)` even on a fresh
target, via both the RPC command API and the raw shell-read. **20/20** reads succeed
once the session is upgraded to meterpreter first. Fix (already existed for
persistence; applied to impact): `impact._find_live_impact_session` upgrades a
command_shell → meterpreter before reading. Without T6, orphan_c would have
"recovered" but never grounded, and we'd have chased it in the campaign logs.

---

## T7 — Capability loss never blacklists a good technique

**Proves.** When a node fails because its *session died* (a capability loss, not a
wrong technique), the system must **not** add that node's technique to the
"already-failed" blacklist — the technique was never at fault, and blacklisting it
would stop the graft from re-using it to re-provision.

**How.** Live orphan run surfaced the bug; locked in by offline unit test
`tests/test_blacklist_capability_vs_technique.py` (4 cases).

**Result — ✅ PASS — and it caught a real bug.** The smoke run found that
`_failed_techniques` was counting a `session_unusable` failure (a capability loss)
as a failed *technique*, which would blacklist the very exploit the graft needs.
Fixed by skipping `_CAPABILITY_LOSS_CATEGORIES` in `_failed_techniques`, and pinned
with the 4-case test (capability-loss categories are skipped; genuine technique
failures are still blacklisted). This is the T-vs-P (technique vs precondition)
distinction enforced in the blacklist path.

---

## What the gate bought us

- **Two invalidating bugs caught before the campaign** (T6 read-zombie, T7 blacklist)
  — either would have produced numbers that looked plausible but were wrong.
- **The three core claims each have an independent smoke check:** detection (T2),
  ablation validity (T3), and grounding integrity (T4) — so the campaign's headline
  isn't resting on a single point of trust.
- **Termination is proven, not assumed** (T5).

The offline checks (T4, T5, T7) live in `tests/` and run in seconds via
`python tests/run_offline.py`; the live checks (T1, T2, T3, T6) are reproducible
against the lab with the scenarios named above.
