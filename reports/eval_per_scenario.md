# Per-scenario breakdown

_Same metrics as the headline table, split by scenario — shows which scenarios each variant fails._


## baseline_impact

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 1 | 100% ± 0 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0.0 ± 0.0 | 403.0 ± 0.0 |

## flaw_persistence

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 1 | 100% ± 0 | 0% ± 0 | 100% ± 0 | 0% ± 0 | 1.0 ± 0.0 | 1018.0 ± 0.0 |

## flaw_privesc

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 8 | 88% ± 35 | 0% ± 0 | 0% ± 0 | 12% ± 35 | 0.6 ± 0.5 | 1490.0 ± 108.1 |
| v_nograft | 10 | 80% ± 42 | 0% ± 0 | 0% ± 0 | 20% ± 42 | 0.5 ± 0.5 | 1498.6 ± 119.5 |

## orphan_a

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 4 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 100% ± 0 | 2.0 ± 0.0 | 1163.0 ± 19.0 |

## orphan_c

| Variant | N | Grounded success | False success | Recovery (flaw_*) | Non-termination | Replan edits | Wall secs |
|---|---|---|---|---|---|---|---|
| v0_full | 10 | 80% ± 42 | 0% ± 0 | 80% ± 42 | 20% ± 42 | 2.0 ± 0.0 | 696.3 ± 257.0 |
| v_nograft | 10 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 0% ± 0 | 2.0 ± 0.0 | 495.4 ± 4.0 |