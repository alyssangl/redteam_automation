# Per-scenario breakdown

_Same metrics as the headline table, split by scenario — shows which scenarios each variant fails._


## flaw_persistence

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 4 | 75% ± 50 | 0% ± 0 | 75% ± 50 | 25% ± 50 | 1.0 ± 0.0 | 1040.5 ± 121.4 |
| v1_noreplan | 4 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0.0 ± 0.0 | 731.5 ± 16.8 |
| v3_noground | 4 | 100% ± 0 | 0% ± 0 | 100% ± 0 | 0% ± 0 | 1.0 ± 0.0 | 974.0 ± 59.0 |
| v4_nodeterm | 5 | 20% ± 45 | 0% ± 0 | 0% ± 0 | 20% ± 45 | 0.0 ± 0.0 | 585.2 ± 503.6 |

## flaw_privesc

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 5 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 40% ± 55 | 0.0 ± 0.0 | 624.8 ± 394.3 |
| v1_noreplan | 2 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0.0 ± 0.0 | 1059.0 ± 22.6 |
| v3_noground | 1 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 100% ± 0 | 0.0 ± 0.0 | 1092.0 ± 0.0 |