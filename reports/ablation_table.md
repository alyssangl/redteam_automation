# Ablation table

_Rows = system variants, cols = metrics. Each cell = mean ± std over all runs of that variant, POOLED across scenarios × reps._

> **Read the per-scenario table (`eval_per_scenario.md`) for the headline.** Recovery is only comparable WITHIN a scenario — pooling it here mixes scenarios with different objectives (e.g. a deterministic impact objective vs. a technique-failure control), so the pooled recovery figure is diluted and not the number to quote.

_Source: 38 valid runs; 2 confounded run(s) discarded (wedged-msfrpcd timeouts / recon-root failures, excluded per protocol — see the per-cell breakdown below)._

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 18 | 83% ± 38 | 0% ± 0 | 44% ± 51 | 17% ± 38 | 1.4 ± 0.8 | 1049.1 ± 452.2 |
| v_nograft | 20 | 40% ± 50 | 0% ± 0 | 0% ± 0 | 10% ± 31 | 1.2 ± 0.9 | 997.0 ± 521.2 |


## Reading it

- **Recovery** is the headline metric for the graft — but read it **per scenario** (above it is pooled). On a capability-loss (orphan_*) scenario, **v0_full** should recover and **v_nograft** should not; on a technique-failure (flaw_*) control the two should behave alike.
- **False success** is re-derived from INDEPENDENT evidence (a root token / a proof-marker read back off the target), never the agent's own findings, and is scoped to privesc+impact. Grounded variants hold it at 0; a grounding-OFF variant (v3_noground / v6_naive) is where it spikes.
- **Non-termination** is capped by the replan budget; deterministic tried-tracking is what keeps it low.

_Variants in this run: v0_full, v_nograft._

## Confounded / excluded cells

_2 of 40 run(s) excluded as lab artifacts (wedged-msfrpcd timeouts, recon/root-node failures), shown per (scenario × variant). A reviewer should confirm the exclusions are NOT concentrated in the variant whose metric we claim (v3_noground for false_success)._

| Scenario \ Variant | v0_full | v_nograft |
|---|---|---|
| flaw_privesc | 2 | · |
| orphan_c | · | · |
| **excluded / variant** | **2** | **0** |

_Most-excluded variant: **v0_full** (2 run(s)). v3_noground has 0 exclusion(s) — NOT the most-excluded — no exclusion bias toward the grounding claim._


## Threats to validity

- **Persistence grounding is findings-derived (C5).** privesc and impact have cheap INDEPENDENT probes (root `id`/`getuid`; a proof-marker read back off the target), but a landed cron/ssh-key/service does not, so its grounding rests on the stage's own findings. `false_success` is therefore SCOPED to privesc+impact; a persistence over-claim is not counted. Widen only once persistence can be grounded independently.
- **Subagent ground-truth capture.** When privesc/impact run as subagents their raw root/probe output is emitted to stdout, which the per-run file log does not capture (it lands in the combined matrix stdout). For those nodes the per-run artifacts can lack the token, so a real escalation may be scored `false_success`. The bias is CONSERVATIVE (never over-credits a claim); routing subagent ground-truth into the per-run log would tighten it.
- **Exclusions.** Confounded cells are dropped as lab artifacts; the per-cell table above lets a reviewer confirm the drops are not concentrated in the grounding-claim variant.
