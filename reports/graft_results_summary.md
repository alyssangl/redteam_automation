# GRAFT — experiment results summary (N=10 campaign)

_For Prof. Didik. Prepared 2026-09-06. All runs on the isolated lab: Metasploitable 3
target (192.168.34.7), Kali attacker + msfrpcd (192.168.34.6), GPT-4o replanner/judge._

## Bottom line

The core claim holds with statistical significance. On a controlled **capability-loss**
break, the full system recovers **8/10** runs versus **0/10** for the ablation that keeps
everything except the graft — **Fisher exact p = 0.0007**. The technique-failure control
shows no separation, confirming the gap is the graft specifically, not general repair. And
across all 38 valid runs the grounded system admitted **zero** unproven successes.

## What was run

40 cells = 2 scenarios × 2 variants × N=10 (38 valid, 2 excluded as lab artifacts):

- **orphan_c** — the headline. A normal chain (recon → access → impact objective) whose
  established session is destroyed **externally, by the harness**, right before the impact
  step. The objective (write a proof file and read it back) can then only be reached by
  re-provisioning a fresh session and re-parenting the objective onto it — i.e. the graft.
- **flaw_privesc** — the control. A wrong exploit module is injected at privilege
  escalation: a **technique** failure that substitution alone can repair, so FULL and
  NO-GRAFT should behave alike.

Variants: **FULL** (complete system) and **NO-GRAFT** (identical, but the capability
branch routes to technique-substitution instead of the graft — a minimal-diff ablation).

## Result 1 — recovery from capability loss (the headline)

| Scenario | Variant | Recovered | Grounded success |
|---|---|---|---|
| orphan_c | **FULL** | **8/10** | 8/10 |
| orphan_c | **NO-GRAFT** | **0/10** | 0/10 |

**FULL 8/10 vs NO-GRAFT 0/10 — Fisher exact (2-sided) p = 0.0007.**

This matches the theory exactly (capability orphaning, Eq. 6): without the graft, the lost
session cannot be restored, so the feasibility gate never opens and recovery is impossible
at any retry budget — hence a clean 0/10, not merely "lower". With the graft, the system
re-provisions a session and completes the orphaned objective 8/10.

## Result 2 — the control (fairness)

| Scenario | Variant | Grounded success |
|---|---|---|
| flaw_privesc | FULL | 7/8 |
| flaw_privesc | NO-GRAFT | 8/10 |

No separation — FULL ≈ NO-GRAFT on a technique failure. This is what makes Result 1
meaningful: the 8-vs-0 gap appears **only** on the capability-loss break, so it is the
graft, not generic plan revision. (Recovery reads 0 for both here by definition: the
privesc subagent fixes the bad module *in-node*, so success does not route through a
replanner-grown node, which is what the "recovered" metric counts. The equal grounded
rates carry the control conclusion.)

## Result 3 — grounding (independent success verification)

**False-success = 0 across all 38 valid runs** (FULL 0/18, NO-GRAFT 0/20). The grounding
oracle never once let an unproven claim become execution state (Δ_A = 0). This is verified
three independent ways: (a) empirically here, 0/38; (b) an offline adversarial test — a
fake `uid=0(root)` / proof marker planted in the agent's own text does not ground, only a
token captured off the target does; (c) by construction — admission is defined over
captured bytes, so Δ_A = 0 whenever admission is on the oracle.

## Honest status and what remains

- **Contribution 1 (the graft): complete and significant.** p = 0.0007.
- **Contribution 2 (the oracle): core claim demonstrated** (Δ_A = 0, three ways above).
  What is **not** yet shown empirically is the *complementary* spike — that with grounding
  OFF, unproven claims are admitted (Δ_A = Δ_R). We attempted this as a self-ablation
  (NO-GROUND / NAIVE on the headline) and found two obstacles: our own stage agents rarely
  overclaim (privesc honestly times out and reports failure rather than claiming false
  root), and the lab's Kali/msfrpcd side degraded during the long batch. The cleaner
  vehicle — already scoped in the paper — is the **third-party-agent row** (apply our
  oracle, unmodified, to an external agent such as HackingBuddyGPT that does overclaim),
  which needs a stable lab and is the recommended next step for this specific number.
- **Generality across placements** (orphan-B / orphan-C at other points in the chain) is
  future work; the current headline is a single, clean placement plus the control.

## Threats to validity (already controlled)

- **Lab artifacts excluded, not hidden.** 2 of 40 runs were confounded (a wedged
  msfrpcd/console) and dropped per protocol; the exclusions are not concentrated in the
  claim variant. The harness now snapshot-restores a fresh target per cell, aborts a batch
  after consecutive confounded cells, and refuses overlapping batches — the three failure
  modes we hit while producing this data, now prevented.
- **Grounding is independent of the acting agent** — the false-success metric is re-derived
  from raw target output, never the agent's own report.
- **Single lab / single target model.** A second target would strengthen external validity.

## Artifacts

`reports/eval_per_scenario.md` (the clean per-scenario table — the numbers above),
`reports/ablation_table.md` (pooled), `eval_results.csv` (one row per run), and the
analysis script `experiments/analyze_eval.py` (Wilson intervals + Fisher exact, pure
Python). Every number here traces to a row in the CSV.
