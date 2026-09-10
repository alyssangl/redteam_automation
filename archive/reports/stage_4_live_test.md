# Stage 4 — Live Test Report

**Stage:** Lower the emission bar. Replanner LLM emits a tiny intent `{action, target_hint, label?, goal?, rationale}`; orchestrator expands to a full `AttackNode` locally (RHOSTS/LHOST/LPORT/RPORT defaulted from graph context).

**Status:** ✅ PASS (after one iteration to add an anti-repetition guard)

**Date:** 2026-05-21
**Run log:** `logs/creme_disk_wipe_192.168.34.7_20260521_110609.log`
**Driver:** `experiments/live_test_stage_4.py`
**Wall time:** 7 min 31 s (11:06:09 → 11:13:40)
**Target:** Metasploitable 3 @ `192.168.34.7`
**Attacker:** Kali @ `192.168.34.6`

---

## What was tested

Same CREME disk_wipe scenario, but the replanner now emits ~4-field intents instead of ~15-field full nodes. The expansion helper `_expand_intent_to_node` fills in `agent_type`, `tool_name`, `target_ip`, `module_options.RHOSTS`, `module_options.RPORT` (looked up by service), `payload_options.LHOST`, and `payload_options.LPORT` from graph context.

## Iteration history

This stage required two follow-up iterations to reach PASS:

| Run | Outcome | Issue |
|---|---|---|
| v1 | Failed | LLM proposed `usermap_script` 8× in a row (10/10 replan budget exhausted) — FAILED entries in context didn't show `module` field, so LLM didn't see what it had tried |
| v2 | Improved | After adding `module` + `commands_to_run` to FAILED context entries, LLM diversified to 2 modules — but still repeated each 4×. Prompt-level "DO NOT propose this same approach again" was ignored by gpt-4o-mini |
| v3 (this) | Pass | Added code-level anti-repetition guard: `_replan_from` rejects a proposal whose `module` (or `commands_to_run` set) exactly matches a previously-failed node. Three unique proposals, guard fired correctly, clean termination |

The anti-repetition guard is rejection-by-observed-failure, distinct from Stage 1's removal of speculative version-table rejection. Stage 1 said "don't reject based on heuristic"; this guard says "don't repeat what literally just failed."

## Observed flow (v3)

| t | Event |
|---|---|
| 11:06:09 | Run starts |
| 11:09:48 | rails_exploit failure (LLM still proposed wrong Rails path) |
| 11:12:31 | Replan 1/10 from `ssh_bruteforce` (gave new edge to existing `persistence`) |
| 11:12:34 | Replan 2/10 from `recon` → NEW NODE `usermap_script` |
| 11:12:56 | Replan 3/10 → NEW NODE `apache_mod_cgi_bash` (diversified) |
| 11:13:19 | Replan 4/10 → NEW NODE `samba_vuln_cve_2017_7494` (diversified again) |
| 11:13:40 | Replan 5/10 → LLM proposed `apache_mod_cgi_bash` again → **`REJECTED ... already tried and failed`** |
| 11:13:40 | Walker has no remaining options → `EXECUTION COMPLETE` |

## Pass criteria

| Criterion | Result | Evidence |
|---|---|---|
| Replanner activates | ✅ | 5 replan attempts |
| LLM emits tiny intents | ✅ | Replanner LLM responses ~150 chars vs. previous ~600 chars; `target_hint` present in each |
| `_expand_intent_to_node` fills defaults | ✅ | Each new node has `module_options.RHOSTS=192.168.34.7`, `payload_options.LHOST=192.168.34.6`, `LPORT=4444`, `RPORT` populated for known modules |
| Proposals diversified (no infinite repeat) | ✅ | 3 unique modules across 4 successful new-node creations |
| Anti-repeat guard fires when LLM repeats | ✅ | Line 2102: `REJECTED exploit/multi/http/apache_mod_cgi_bash: already tried and failed in ['apache_mod_cgi_bash']` |
| Run completes cleanly | ✅ | `EXECUTION COMPLETE` |
| Wall time comparable to baseline | ✅ | 7m 31s vs. Stage 3's 7m 20s |

## Pre-existing issue surfaced (not Stage 4's fault, worth a follow-up)

The LLM consistently **hallucinates module paths**: it proposes `exploit/linux/samba/usermap_script` (doesn't exist) and `exploit/linux/samba/samba_vuln_cve_2017_7494` (doesn't exist). MSF rejects both with `Failed to load module`. The correct paths are `exploit/multi/samba/usermap_script` and `exploit/linux/samba/is_known_pipename`.

This was also happening under the verbose schema in Stages 1-3 — the verbose emission just made the wrong fields more elaborate, not the module path more accurate. Stage 4 exposed it more visibly because the LLM's emission is now mostly *just* the module path, so a wrong path stands out.

A correct fix would be to query MSF RPC for module existence before adding the node and reject hallucinated paths. That crosses Stage 1's "don't reject on heuristic" line, but module existence is a deterministic check, not a heuristic — defensible. Out of scope for Stage 4; worth a memory.

## Verdict

Stage 4 PASSES. The emission bar is lowered — replanner LLM payloads are ~25% the size they were. Expansion correctly fills defaults. The added anti-repetition guard prevents the LLM's known weakness for repeating itself from burning the replan budget. Wall time is back to baseline.

This completes all four stages of the judge redesign plan from `Lessons from VulnBot.pdf`.
