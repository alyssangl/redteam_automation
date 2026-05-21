# Stage 2 — Live Test Report

**Stage:** Feed prose context to the replanner — stop stripping `raw_nmap_output` from stuck-node findings, add last 3 `CommandRecord.output` tails (capped 2 KB each).

**Status:** ✅ PASS

**Date:** 2026-05-21
**Run log:** `logs/creme_disk_wipe_192.168.34.7_20260521_101128.log`
**Driver:** `experiments/live_test_stage_2.py`
**Wall time:** 7 min 35 s (10:11:28 → 10:18:26)
**Target:** Metasploitable 3 @ `192.168.34.7`
**Attacker:** Kali @ `192.168.34.6`

---

## What was tested

Same scenario as Stage 1 (CREME disk_wipe graph with `explore=True`), but now inspecting the **content** of the replan context dumped at DEBUG level. The orchestrator's debug line was bumped from `context[:1000]` to the full context so we can grep for the new sections.

## Observed flow

- Replanner activated twice (after rails_exploit retries exhausted, then again after `persistence` MSF module failed).
- Both replans dumped the full context (3703 and 3720 chars) to the log file.
- Both contexts contained the new `RECENT COMMAND OUTPUT` section with the real tails from msf_console commands — including the SSH bruteforce output that revealed `vagrant:vagrant` credentials and the `SSH session 2 opened` line.
- Second replan added `persistence_setup` (cron-job node); it executed in 4s with `success=true`.

## Pass criteria

| Criterion | Result | Evidence |
|---|---|---|
| Replanner activated | ✅ | 2× `Stuck at 'ssh_bruteforce'` (lines 201, 440) |
| Context dumped in full | ✅ | `Context (full, 3703 chars)` and `Context (full, 3720 chars)` |
| `RECENT COMMAND OUTPUT` section present | ✅ | Header at line 283 (and again at 522) of the log |
| Command `output_tail` contains real prose, not just typed findings | ✅ | Line 301: full SSH bruteforce output including `Success: 'vagrant:vagrant'` and `SSH session 2 opened (...) at 2026-05-20 22:14:02 -0400` |
| `exit_code` field captured | ✅ | Present in JSON (null for msf_console — those commands don't surface an exit code, which is correct) |
| Run completes cleanly | ✅ | `EXECUTION COMPLETE` at line 604; replanner-issued `persistence_setup` ran in 4s and succeeded |

## What was NOT exercised live

`raw_nmap_output` preservation only matters when the stuck node IS the recon node (other nodes don't have that field in their `findings`). In both replan calls in this run, the stuck node was `ssh_bruteforce`, so `raw_nmap_output` wasn't in scope.

That case is covered by offline test `experiments/test_stage_2.py` Test 1, which builds a stuck-recon-node scenario with a synthetic `NMAP_OUTPUT_MARKER` and asserts the marker reaches the LLM context. Test 2 covers the 8 KB cap on huge nmap dumps. All 15 offline checks pass.

## Verdict

Stage 2 PASSES. Live evidence: the replanner now sees real banners, stderr, and command outputs from the most recent steps — exactly what an operator would read. Offline tests cover the raw_nmap_output preservation and the 8 KB cap edge case.

## Side observations

- The `DETECTED SERVICES` block (already present from Stage 1's commit) and the new `RECENT COMMAND OUTPUT` block now overlap somewhat — both surface bits of recon. Not a problem; they show different views (structured ports vs. raw command-by-command). Stage 3's judge can decide what's load-bearing.
- The orchestrator marks a session-command node `success=True` whenever the underlying SSH session returns anything, regardless of whether the action actually achieved its goal (line 596: `persistence_setup` "succeeded" but its output was `(no output)`). Same false-positive pattern as Stage 1's `persistence_service_backdoor`. Worth a memory but out of scope here.
