# Per-scenario breakdown

_Same metrics as the headline table, split by scenario — shows which scenarios each variant fails._


## flaw_persistence

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 4 | 75% ± 50 | 0% ± 0 | 75% ± 50 | 25% ± 50 | 1.0 ± 0.0 | 1040.5 ± 121.4 |
| v1_noreplan | 4 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0.0 ± 0.0 | 731.5 ± 16.8 |
| v3_noground | 4 | 100% ± 0 | 0% ± 0 | 100% ± 0 | 0% ± 0 | 1.0 ± 0.0 | 974.0 ± 59.0 |
| v4_nodeterm | 2 | 50% ± 71 | 0% ± 0 | 0% ± 0 | 50% ± 71 | 0.0 ± 0.0 | 1130.0 ± 158.4 |

## flaw_privesc

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 1 | 100% ± 0 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0.0 ± 0.0 | 812.0 ± 0.0 |