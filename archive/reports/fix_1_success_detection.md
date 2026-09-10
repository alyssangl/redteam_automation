# Fix 1 — Command Failure Detection — Live Test Report

**Fix:** Replace the loose `"error" / "not found"` substring heuristic in
`_execute_session_commands` / `_execute_ssh_commands` with a proper
failure-pattern scan via `_command_output_indicates_failure`. Now detects:
Permission denied, No such file or directory, cannot access, command not
found, Operation not permitted, Connection refused, exec format error,
syntax error, "does not exist", and SSH/exit-code wrapper failures.

**Status:** ✅ PASS

**Date:** 2026-05-21
**Run logs:**
- Disk-wipe re-run (Fix 1 path didn't get exercised this run): `logs/creme_disk_wipe_192.168.34.7_20260521_121458.log`
- **Focused 2-node test (the conclusive verification):** `logs/fix1_focused_192.168.34.7_20260521_122433.log`

**Drivers:** `experiments/live_test_fix_1.py` and `experiments/live_test_fix_1_focused.py`
**Target:** Metasploitable 3 @ `192.168.34.7`
**Attacker:** Kali @ `192.168.34.6`

---

## Why this fix

Across Stages 1, 2, and 3's live tests, every replanner-issued
session-command node was marked `success=True` even when its commands
clearly failed:

| Run | Node | Real output | Old verdict |
|---|---|---|---|
| Stage 1 | `persistence_service_backdoor` | `Permission denied` x2 + `cannot access ... No such file or directory` + `file does not exist` | SUCCESS (false positive) |
| Stage 2 | `persistence_setup` | `(no output)` (all 1 command) | SUCCESS (ambiguous; left as-is) |
| Stage 3 | `persistence_ssh_key` | `(no output)` (single command) | SUCCESS (ambiguous; left as-is) |

The old heuristic was:
```python
if "error" in output.lower() and "not found" in output.lower():
    success = False
```
That requires both substrings AND in the same output. "Permission denied" matches neither. "No such file or directory" matches neither (no "error" word).

Result: the orchestrator couldn't tell when its own replanner-issued steps had failed. The replanner therefore couldn't get an honest signal — it thought every proposed step succeeded, so it had nothing to react to.

## The fix in one line

A focused failure-indicator list scanned case-insensitively against each
command's output. If any phrase matches, the node is marked FAILED
with a summary that names the matched phrase. `(no output)` is intentionally
NOT a failure on its own — many useful commands legitimately produce nothing.

## Focused live test

Built a 2-node graph that deterministically exercises the path:

```
ssh_bruteforce (vagrant:vagrant)
       │ on_success
       ▼
perm_denied:
  echo 'pwned' > /etc/shadow        (must be Permission denied as vagrant)
  cat /etc/shadow_does_not_exist    (must be No such file or directory)
```

Run output (verbatim from log):

```
12:24:51 [INFO]   [ssh_bruteforce] STATUS → success: ... session 9
12:24:57 [INFO]   [direct]   -bash: line 1: /etc/shadow: Permission denied
12:25:02 [INFO]   [direct]   cat: /etc/shadow_does_not_exist: No such file or directory
12:25:02 [WARNING] [direct] Command failed ('permission denied'): echo 'pwned' > /etc/shadow
12:25:02 [WARNING] [perm_denied] Direct execution failed: Command failed (...)
12:25:02 [ERROR]   [perm_denied] STATUS → failed: Command failed ('permission denied'): ...
```

| Pass criterion | Observed | Status |
|---|---|---|
| `ssh_bruteforce` opens session | Session 9 with vagrant | ✅ |
| `perm_denied` produces Permission denied + No such file or directory | Both outputs verbatim in log | ✅ |
| New `Command failed (...)` warning fires | Line 68 of log | ✅ |
| Node marked FAILED (not SUCCESS) | Line 72 | ✅ |
| `findings.success == False` | Line 71 | ✅ |
| Summary names the matched failure phrase | `Command failed ('permission denied')` | ✅ |

**Before Fix 1**, this exact node would have been marked SUCCESS. The
proof: the inputs match neither `"error" in output AND "not found" in output`
(old session-cmd check) nor `"failed" in output OR "error" in output` (old
SSH check).

## Side note on the disk-wipe re-run

The first live test (`live_test_fix_1.py`, full disk-wipe graph) completed
cleanly but didn't exercise the session-command failure path because the
LLM's replanner took a different exploration route this run — it proposed
MSF modules rather than session-command nodes. That's fine; the failure-
detection path only fires on session/SSH commands, and the focused test
proves it works deterministically. The non-deterministic full-graph run
just shows there's no regression on the MSF path.

## Offline test coverage

`experiments/test_fix_1_success_detection.py`: 26/26 checks pass. Covers:
- All 8 documented failure phrases are detected (verbatim outputs from
  Stage 1's log + common SSH/connection errors)
- 7 legitimate output shapes (`uid=...`, empty, `(no output)`, `ls`-style,
  copy success) are correctly spared
- `_execute_session_commands` end-to-end: catches Permission denied
- `_execute_session_commands` end-to-end: keeps SUCCESS on quiet legit commands
- `_execute_ssh_commands` end-to-end: catches exit-code-wrapped SSH failures
- First-failure-wins semantics (commands still all execute, but verdict is failure)

Also re-ran all four stages' tests as regression: 9 + 15 + 20 + 44 = 88
prior checks still pass. (One small update was needed to `test_stage_1.py`:
its LLM stub still used Stage 0's verbose `new_node` schema, which Stage 4
deprecated. The test now uses the tiny-intent schema.)

## Verdict

Fix 1 PASSES. The orchestrator now produces honest failure verdicts on
session-command and SSH-command nodes. The replanner finally gets an
accurate signal when its proposals didn't actually work — which makes
the judge redesign's other improvements actually measurable.

## What remains broken (memory items, not addressed here)

1. **LLM hallucinates MSF module paths** (`exploit/linux/samba/usermap_script`
   doesn't exist). Stage 4's anti-repeat guard catches it on the second
   try, but the first attempt still wastes an MSF run. Fix would be an
   MSF RPC module-existence check.

2. **`adapt` is a no-op without `module_options_alternatives`** configured
   on the node. Judge says "tweak TARGETURI" but the node has no alts for
   TARGETURI, so the next retry is identical. Needs hint-to-field plumbing.
