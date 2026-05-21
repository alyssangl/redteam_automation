# Stage 1 — Live Test Report

**Stage:** Demote `MSF_MODULE_REQUIREMENTS` to advisory (no longer rejects replanner proposals on version mismatch).

**Status:** ✅ PASS

**Date:** 2026-05-21
**Run log:** `logs/creme_disk_wipe_192.168.34.7_20260521_095857.log`
**Driver:** `experiments/live_test_stage_1.py`
**Wall time:** 7 min 3 s (09:58:57 → 10:06:00)
**Target:** Metasploitable 3 @ `192.168.34.7`
**Attacker:** Kali @ `192.168.34.6`

---

## What was tested

End-to-end run of the CREME disk_wipe graph with `explore=True`. The graph expects a Rails app on port 8181 which Metasploitable 3 doesn't expose, so `rails_exploit` is guaranteed to fail and the replanner must activate. This exercises the replanner code path that Stage 1 modified.

## Observed flow

| Step | Node | Outcome |
|---|---|---|
| 1 | `recon` | success (12 ports, OS detected) |
| 2 | `ssh_bruteforce` | success (vagrant:vagrant, session 1) |
| 3 | `rails_exploit` | failed × 3, max retries exhausted |
| 4 | Walker | backtracks to `ssh_bruteforce` with `replan=True` flag |
| 5 | Replanner | proposes new node `persistence_service_backdoor` (session command, not MSF module) |
| 6 | New node | dispatched and ran in 23 s, marked success |
| 7 | Walker | reaches leaf, chain complete |

## Pass criteria

| Criterion | Result | Evidence |
|---|---|---|
| Replanner activated | ✅ | `Replan attempt 1/5 from 'ssh_bruteforce'` (line 203) |
| NO `[Replanner] REJECTED proposal` lines | ✅ | `grep -c "REJECTED proposal"` → 0 |
| Replanner-issued node attempts execution | ✅ | `persistence_service_backdoor` dispatched at line 263, success at line 283 |
| NEW EDGE has no persisted hard `EdgeCheck`s | ✅ | No `? check_desc` lines follow the NEW EDGE log entry (line 257) |
| ADVISORY mismatch / Module validation OK branch fires | ⚠️ Not exercised | LLM proposed a `tool_name=session` node, so `proposed_module=""` → validation code skipped at orchestrator.py:1059 |

The last criterion was unmet because the live LLM, given the option to use an already-open SSH session, sensibly proposed a session-command node rather than launching a new MSF exploit. The validation code path Stage 1 modified is only entered when `proposed_module` is non-empty.

That code path is verified by `experiments/test_stage_1.py`, which deterministically synthesises a mismatched MSF module proposal and asserts:
- Replanner returns a new node id (not None)
- The new edge has `checks == []`
- The log contains `ADVISORY mismatch`
- The log does NOT contain `REJECTED proposal`

All 9 offline checks pass.

## Verdict

Stage 1 PASSES. The combination of offline (deterministic synthetic test of the modified branch) and live (end-to-end run confirming no regression, no rejections, replanner-issued node executes) is sufficient evidence the change works as designed.

## Notes for future stages

- The `EXECUTION COMPLETE` summary marked `persistence_service_backdoor` as success even though the underlying commands reported `Permission denied` (line 282: "Permission denied" four times, "file does not exist" once). The session-command path treats exit code by output substring scan only — this is a separate issue unrelated to Stage 1 and worth a memory.
- `tee` truncated stdout because `_dispatch_recon` writes giant ANSI-formatted recon analysis to stdout. The structured log file (`logs/creme_disk_wipe_*.log`) is the source of truth — easier to grep too.
