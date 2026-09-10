# Ablation results — summary & threats to validity

_Generated from `eval_results.csv` (parse_eval → build_table). 15 valid runs; 7
confounded runs discarded per protocol. Lab: Metasploitable 3 target (.7),
Kali/msfrpcd attacker (.6)._

## What we set out to test

The paper's claim is **grounded, failure-driven kill-chain adaptation**: the plan
restructures itself in response to *verified* failures, via a determinism-meets-LLM
loop that (a) recovers from injected failures, (b) doesn't hallucinate success, and
(c) doesn't loop. The ablation removes one layer at a time and watches a metric move.

## Two real results

### 1. Replanner drives recovery (clean, quantitative)
On `flaw_persistence` (a kill-chain with a deliberately-broken persistence step):

| Variant | N | Recovered | Grounded success |
|---|---|---|---|
| **v0 full** | 4 | **3/4** | 3/4 |
| **v1 −replanner** | 4 | **0/4** | 0/4 |

Removing the L3 replanner collapses recovery from 3/4 to **0/4** — the full system
grows an alternative persistence technique and reaches the objective; without the
replanner the broken step is a dead end. This is the headline ablation contrast and
it holds on live data.

### 2. Docker-group privesc recovery now works (qualitative, thin N)
`flaw_privesc` injects a **bogus privilege-escalation module**; the privesc subagent
must recover. Before this session it scored **0/5** (the subagent burned its whole
time-box on one losing vector and never tried the winning one). After the fixes this
session — 600s time-box, a `docker_group` technique (MS3's `boba_fett` is in the
`docker` group ⇒ mount host FS ⇒ root), a corrected SUID-rootbash path, and grounding
that binds to the executor's captured `euid=0(root)` — a clean run goes:

`recon ✓ → gain_access ✓ → escalate: root via docker_group ✓ → proof-drop ✓ = 100%`

**Valid `flaw_privesc` v0 cells: 1/1 grounded root** (r0 = 100%; r1 also reached root
via docker before an unrelated `file_drop` hang confounded the cell). The capability
is demonstrated end-to-end; the sample is thin (see threats below).

## Full table

See `ablation_table.md` (aggregate) and `eval_per_scenario.md` (per-scenario). Note
the aggregate v0/v1/v3/v4 rows are currently dominated by `flaw_persistence` — the
scenario with enough valid cells.

## Threats to validity (honest)

- **Lab flakiness capped the sample.** msfrpcd wedges (SIGTERM-ignoring stuck daemon;
  now force-killed per cell) and — more fundamentally — raw MSF `command_shell` reads
  race, so the `impact`/`file_drop` stage frequently hangs to the 40-min per-cell cap.
  ~30% of runs confounded, and it prevented completing the `flaw_privesc` reps and the
  whole `goal_only` scenario. Confounded runs are **excluded**, not counted as failures.
- **Thin N on `flaw_privesc`** (1 valid v0 cell). The result is a real capability
  demonstration, not a statistically-powered rate.
- **The grounding contrast (v3 −grounding → false-success↑) is NOT shown here.** V3
  gates grounding only in privesc/impact (documented), and every `flaw_privesc` /
  `goal_only` v3 cell confounded, so the money metric for the grounding claim has no
  clean cells yet. On `flaw_persistence` (where V3 doesn't gate grounding by design)
  v3 correctly shows no change. False-success is 0 everywhere in the valid set.
- **Single lab / few targets** — the standing generalization limit.

## To turn this into a full table

Not more model work — **lab hardening**: move `impact` (and any command_shell reads)
onto meterpreter for reliable reads, and/or fix the console leak that wedges msfrpcd
mid-cell; then re-run `flaw_privesc` + `goal_only` for N=5 and the v3 grounding row.
The `--skip-done` matrix resumes and only re-runs the confounded/missing cells.
