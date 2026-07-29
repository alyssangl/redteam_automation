# Ablation table

_Rows = system variants, cols = metrics. Each cell = mean ± std over all runs of that variant (scenarios × reps). Recovery is computed over flaw_* scenarios only._

_Source: 15 valid runs; 7 confounded run(s) discarded (wedged-msfrpcd timeouts, excluded per protocol)._

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 5 | 80% ± 45 | 0% ± 0 | 60% ± 55 | 20% ± 45 | 0.8 ± 0.4 | 994.8 ± 146.6 |
| v1_noreplan | 4 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0.0 ± 0.0 | 731.5 ± 16.8 |
| v3_noground | 4 | 100% ± 0 | 0% ± 0 | 100% ± 0 | 0% ± 0 | 1.0 ± 0.0 | 974.0 ± 59.0 |
| v4_nodeterm | 2 | 50% ± 71 | 0% ± 0 | 0% ± 0 | 50% ± 71 | 0.0 ± 0.0 | 1130.0 ± 158.4 |


## Reading it

- **v3_noground** should show **False success** spiking vs v0_full (grounding is what suppresses unproven claims).
- **v1_noreplan** should show **Recovery** collapsing (the replanner is what restructures around the injected failure).
- **v4_nodeterm** should show **Non-termination** rising (deterministic tried-tracking is what prevents technique loops).
- **v6_naive** is the external floor: no graph, judge, or replanner.
