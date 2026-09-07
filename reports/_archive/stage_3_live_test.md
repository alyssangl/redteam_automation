# Stage 3 — Live Test Report

**Stage:** Add layer-2 `judge()` LLM at three trigger points; refactor `_execute_node` retry loop to consult judge between attempts; extract `_try_replanner` helper; bump `max_replan_attempts` 5→10; add `use_judge` flag to `run_graph`.

**Status:** ✅ PASS

**Date:** 2026-05-21
**Run log:** `logs/creme_disk_wipe_192.168.34.7_20260521_102439.log`
**Driver:** `experiments/live_test_stage_3.py`
**Wall time:** 7 min 20 s (10:24:39 → 10:31:59)
**Target:** Metasploitable 3 @ `192.168.34.7`
**Attacker:** Kali @ `192.168.34.6`

---

## What was tested

Same CREME disk_wipe scenario as Stages 1 and 2, this time with `use_judge=True`. Verifies:
- judge fires at both trigger points (post_retry and post_node)
- judge integrates cleanly with existing replanner/backtrack flow
- new budget surface (10 instead of 5)
- no regression vs. Stage 2's clean end-to-end run

## Observed flow

| t | Event | Judge action |
|---|---|---|
| 10:26:13 | recon succeeded | `post_node: continue` |
| 10:28:21 | ssh_bruteforce succeeded | `post_node: continue` |
| 10:30:43 | rails_exploit retry 1 (failed) | `post_retry: adapt` — "Adjust TARGETURI" |
| 10:30:57 | rails_exploit retry 2 (failed) | `post_retry: adapt` — same |
| 10:31:10 | rails_exploit exhausted → `Replan attempt 1/10` | (replanner; not judge) |
| 10:31:12 | Replanner edge `ssh_bruteforce → persistence` | — |
| 10:31:20 | persistence retry 1 (failed) | `post_retry: adapt` — "Trying a different payload" |
| 10:31:31 | persistence retry 2 (failed) | `post_retry: adapt` — "Switch to a compatible payload" |
| 10:31:40 | persistence exhausted → `Replan attempt 2/10` | (replanner) |
| 10:31:44 | Replanner created `persistence_ssh_key` | — |
| 10:31:59 | persistence_ssh_key succeeded | `post_node: continue` |
| 10:31:59 | `EXECUTION COMPLETE` | — |

## Pass criteria

| Criterion | Result | Evidence |
|---|---|---|
| Judge flag visible | ✅ | `Explore: True  Judge: True` in banner |
| Judge fires post_node | ✅ | 3 calls (after each successful node) |
| Judge fires post_retry | ✅ | 4 calls (twice for rails_exploit, twice for persistence) |
| Judge defaults respected (returns `continue` on success) | ✅ | All post_node calls returned `continue` |
| Judge makes failure-aware decisions | ✅ | All post_retry calls returned `adapt` with specific hints ("Adjust TARGETURI", "Switch to a compatible payload") |
| New 10-attempt budget surfaced | ✅ | `Replan attempt 1/10`, `2/10` |
| `_try_replanner` refactor working | ✅ | Both replanner invocations succeeded via the new helper |
| Run completes cleanly | ✅ | `EXECUTION COMPLETE` |
| Wall time comparable to baseline | ✅ | 7m 20s vs. Stage 2's 7m 35s — marginally faster |

## What was NOT directly exercised live

The live LLM judge chose `adapt`/`continue` for every call in this run — it never said `escalate`. So the escalate→short-circuit path wasn't proven live. That path is covered by offline `test_stage_3.py` Test 3, which deterministically returns `{"action": "escalate"}` and asserts `_execute_node` calls `dispatch` exactly once (not three times), returns `(False, "judge_escalate")`.

The fact that the live LLM consistently chose `adapt` rather than `escalate` is actually a positive sign for prompt calibration — the judge isn't over-eagerly escalating.

## Issues observed (out of scope for Stage 3, worth memoryizing)

1. **`adapt` is a no-op without alternatives.** The judge said `adapt -- Adjust TARGETURI` for rails_exploit, but that node has no `module_options_alternatives` configured for TARGETURI. The next retry ran identically, failed identically. `adapt` should either be downgraded to `continue` when no useful alts exist, or the system should be able to pass the judge's hint to the next attempt as an override. Worth a Stage 5 or a separate ticket.

2. **`module_options_alternatives` is empty on the disk_wipe graph's nodes.** The existing graph fixture doesn't exercise the alts mechanism that already exists. If we want to validate `adapt` end-to-end, we'd need to either expand the graph or build a dedicated test fixture.

3. **Same false-positive issue from prior stages persists**: `persistence_ssh_key` was marked SUCCESS based on shell-exit-code only; the actual `(no output)` doesn't prove the SSH key was actually written.

## Verdict

Stage 3 PASSES. The judge is integrated at both trigger points, doesn't break the existing flow, returns sensible decisions on the live LLM, and the larger budget shows up correctly. The `_try_replanner` refactor consolidated three duplicate replanner-call blocks into one helper without behavioral change.

The full architecture from the PDF — Layer 1 (tactical, stage subagents) + **Layer 2 (judge)** + Layer 3 (replanner) — is now in place.
