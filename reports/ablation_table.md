# Ablation table

_Rows = system variants, cols = metrics. Each cell = mean ± std over all runs of that variant (scenarios × reps). Recovery is computed over flaw_* scenarios only._

_Source: 25 valid runs; 9 confounded run(s) discarded (wedged-msfrpcd timeouts, excluded per protocol)._

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 9 | 33% ± 50 | 0% ± 0 | 33% ± 50 | 33% ± 50 | 0.4 ± 0.5 | 809.6 ± 362.3 |
| v1_noreplan | 6 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0.0 ± 0.0 | 840.7 ± 169.9 |
| v3_noground | 5 | 80% ± 45 | 0% ± 0 | 80% ± 45 | 20% ± 45 | 0.8 ± 0.4 | 997.6 ± 73.5 |
| v4_nodeterm | 5 | 20% ± 45 | 0% ± 0 | 0% ± 0 | 20% ± 45 | 0.0 ± 0.0 | 585.2 ± 503.6 |


## Reading it

- **v3_noground** should show **False success** spiking vs v0_full (grounding is what suppresses unproven claims).
- **v1_noreplan** should show **Recovery** collapsing (the replanner is what restructures around the injected failure).
- **v4_nodeterm** should show **Non-termination** rising (deterministic tried-tracking is what prevents technique loops).
- **v6_naive** is the external floor: no graph, judge, or replanner.
