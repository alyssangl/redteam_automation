# Replanner Reliability — Investigation + Fix Plan

Follow-up to the judge redesign. After Stages 1-4 + Fix 1 fixed the orchestrator's **process** around replanning (when it fires, what it sees, how it emits, how it detects command failures), live runs show the **content** of replanner proposals is still mostly bad. The baseline graph (`disk_wipe_success_graph`) runs 6/6 nodes successfully when steps are hand-authored — proving the executor is sound. The pipeline that doesn't work is the LLM picking what to do next.

This document inventories the failure modes from real logs, identifies the bottleneck, and proposes 4 stages of fixes.

---

## The bottleneck, in evidence

### 1. Hallucinated MSF module paths (20% of proposals across all runs)

Grepping `Failed to load module` across all replan runs:
```
exploit/linux/local/service_persistence
exploit/linux/samba/samba_vuln_cve_2017_7494
exploit/linux/samba/usermap_script
```
None of these exist in real MSF. The correct paths are:
- `exploit/linux/local/service_persistence` → unclear, possibly different namespace
- `is_known_pipename` (CVE-2017-7494) is at `exploit/linux/samba/is_known_pipename`
- `usermap_script` is at `exploit/**multi**/samba/usermap_script` (not `/linux/`)

The LLM is generating module paths from training-data memory, not ground truth.

### 2. Module exists but proposal is wrong-fit (most remaining failures)

Top "Exploit completed but no session" by module, across runs:
| Count | Module | Why it failed |
|---|---|---|
| 80 | `exploit/linux/samba/usermap_script` | Doesn't exist; never loaded |
| 48 | `exploit/multi/http/apache_mod_cgi_bash` | Apache exists but no vulnerable CGI path on this MS3 image |
| 32 | `exploit/multi/samba/usermap_script` | Loads, but Samba 4.3.11 doesn't match required 3.0.20-3.0.25 |
| 16 | `exploit/unix/ftp/proftpd_modcopy_exec` | Real exploit. Failed: `"directory not writable? website path"` (SITEPATH wrong) |
| 16 | `samba_vuln_cve_2017_7494` | Doesn't exist; never loaded |

Concrete MSF failure outputs we have in logs but throw away:
- `Exploit aborted due to failure: unknown: Failure copying PHP payload to website path, directory not writable?` (proftpd — needs different SITEPATH)
- `Exploit failed: cmd/unix/reverse_python is not a compatible payload` (payload picked wrong for the target)
- `Caution: Cookie not found, maybe you need to adjust TARGETURI` (rails — needs path tweak)
- `Exploit aborted due to failure: bad-config: No cookie found and no name given` (rails — wrong RAILS_ENV / endpoint)

The orchestrator collapses ALL of these into `summary: "Exploit completed but no session created"`. The replanner never sees the actual reason.

### 3. Session privilege info captured but never surfaced

Every SSH brute-force run produces this in MSF output:
```
Success: 'vagrant:vagrant' 'uid=900(vagrant) gid=900(vagrant) groups=900(vagrant),27(sudo) ...'
```
**vagrant is in the sudo group** — passwordless privesc is available. But `_parse_msf_output` sets `access_level: "unknown"` and never updates it. The replanner doesn't know it has sudo, so it proposes commands that need root (e.g., `echo X > /etc/init.d/persistent_backdoor` — Permission denied) instead of `sudo X`.

### 4. LHOST silently defaults to 127.0.0.1 when no payload is set

Logs from Stage 4 v1/v2 contain 70 instances of `You are binding to a loopback address by setting LHOST to 127.0.0.1`. Tracing the code: `_expand_intent_to_node` sets `payload_options = {"LHOST": graph.attacker_ip, "LPORT": 4444}` — but it leaves `payload` empty. `_execute_msf_module` only emits `set LHOST` / `set LPORT` commands **if `payload` is non-empty**. So when the LLM doesn't pick a payload (which is most of the time in tiny-intent mode), MSF uses the module's default payload, and our LHOST/LPORT never reach the console. MSF then defaults LHOST to 127.0.0.1 — the reverse handler binds to loopback and never gets the callback.

### 5. LLM ignores prompt-level "don't repeat" but obeys programmatic rejection

In Stage 4 v2, the LLM proposed `usermap_script` 4 times even with explicit prompt rule "DO NOT propose this same approach again" and the FAILED entries in context showing the module path. After Stage 4 v3 added a code-level anti-repeat guard, repetition stopped. gpt-4o-mini doesn't reliably follow soft constraints; it does respect hard rejection.

---

## What the bottleneck IS, in one sentence

**The replanner LLM picks exploit modules from training memory rather than from the actual MSF catalog, and the orchestrator gives it neither the ground-truth catalog nor the rich failure detail that would let it self-correct.**

---

## Plan: four stages

Same structure as `judge_redesign_plan.md`. Each stage has goal, code delta, offline correctness check, live test, and risk/rollback. Ordered by impact / reversibility.

### Stage A — Pre-validate proposed modules against MSF's actual catalog

**Goal:** Stop module-path hallucination at the source. If the LLM proposes a module that MSF doesn't have, reject programmatically instead of waiting for MSF to fail to load it.

This is **deterministic ground-truth validation**, distinct from Stage 1's removal of *heuristic* version-table rejection. Stage 1's argument was "don't reject based on a guess about whether something will work." This stage's argument is "if MSF literally does not have this module, the proposal cannot run — that's not a guess."

**Code delta** (`core_agents/orchestrator.py`):
1. Lazy-load + cache an `_MSF_MODULE_CATALOG: set[str]` at first use. Query via `tools.metasploit_tools.msf_session.client.modules.exploits` (and `.auxiliary`, `.post`).
2. New helper `_module_exists_in_msf(module_path: str) -> bool` — fast set membership.
3. In `_replan_from`'s `use_module` branch (right before the Stage 4 anti-repeat guard): if `_module_exists_in_msf(new_node.module) is False`, log a clear rejection and return None.
4. Tag the rejection in logs differently from anti-repeat so it's diagnosable: `[Replanner] REJECTED <module>: not in MSF catalog (likely hallucinated)`.

**Correctness check (offline):** `experiments/test_stage_a_msf_catalog.py`
- Patch the catalog loader to return a known fake set.
- Assert hallucinated paths (`exploit/linux/samba/usermap_script`, `exploit/linux/local/service_persistence`) get rejected.
- Assert real paths in the fake catalog get accepted.
- Assert the catalog is loaded exactly once (no per-call RPC roundtrip).

**Live test:** Re-run `live_test_fix_1.py` (full disk_wipe with replanner). Pass criteria:
- No `Failed to load module` lines anywhere in the log.
- At least one `REJECTED ... not in MSF catalog` line, OR all proposals are valid paths.

**Risk:** Low. Worst case: catalog query takes 1-2s on first use. Cached afterwards.
**Rollback:** Single helper + one rejection block. Trivial revert.

---

### Stage B — Extract & surface session privilege

**Goal:** When the orchestrator opens a session, parse the user/group info out of the MSF output and surface it everywhere downstream (findings, replanner context, judge context). Stop the LLM from proposing root-only operations as vagrant.

**Code delta** (`core_agents/orchestrator.py`):
1. New helper `_extract_privilege_from_msf_output(output: str) -> dict` — parse `uid=N(name)`, `gid=N(name)`, `groups=N(name)...`. Return:
   ```python
   {"uid": 900, "user": "vagrant", "gid": 900,
    "groups": ["vagrant", "sudo"], "in_sudo_group": True, "is_root": False}
   ```
2. In `_parse_msf_output` after a session opens, call the helper on the same output, store result in `findings["session_user_info"]`. Set `findings["access_level"]` to `"root"` / `"user_with_sudo"` / `"user"` accordingly.
3. In `_build_judge_context` and `_replan_from`'s context, surface user info prominently:
   ```
   SESSION PRIVILEGE: vagrant (uid=900), in groups [vagrant, sudo].
   Can sudo: YES (NOPASSWD likely — verify before relying on it).
   Cannot write to /etc, /var, /usr without sudo.
   ```
4. Update `REPLAN_PROMPT` to emphasise: *check SESSION PRIVILEGE before proposing root-only paths; prefix commands with `sudo -n` if needed*.

**Correctness check (offline):** `experiments/test_stage_b_privilege.py`
- Feed synthetic MSF output strings; assert parser extracts correct uid/groups.
- Edge cases: meterpreter session with no `uid=` line, root session (uid=0), session with extra groups.
- Assert `findings.access_level` reflects sudo group membership correctly.

**Live test:** Re-run `live_test_fix_1.py`. Pass criteria:
- After ssh_bruteforce, `findings["access_level"]` is `"user_with_sudo"` (not `"unknown"`).
- If any replan fires, its context includes the `SESSION PRIVILEGE` block.

**Risk:** Low. Adds info, doesn't remove anything.
**Rollback:** Revert helper + remove 2-3 context lines.

---

### Stage C — Capture MSF failure causes (not just "no session")

**Goal:** When MSF runs an exploit and prints a specific reason for failure, capture that reason. Surface it in the failed-node entry in the replanner's context so the LLM can pivot intelligently.

Today, an MSF exploit that prints
```
[-] Exploit aborted due to failure: unknown: Failure copying PHP payload to website path, directory not writable?
```
gets collapsed to `summary: "Exploit completed but no session created via exploit/unix/ftp/proftpd_modcopy_exec"`. The actual cause — "SITEPATH not writable" — is lost.

**Code delta** (`core_agents/orchestrator.py`):
1. In `_parse_msf_output`, when no session is detected, scan output for known MSF failure patterns:
   - `Exploit aborted due to failure: <category>: <message>`
   - `Failed: <module>` (load failure)
   - `Exploit failed: <payload> is not a compatible payload` → `incompatible_payload`
   - `Caution: <warning>` → captured separately
   - `bad-config: <message>` → `config_problem`
   - `directory not writable` → `writable_path_missing`
   - `Cookie not found` / `adjust TARGETURI` → `wrong_targeturi`
2. Store as `findings["failure_cause"]` (specific phrase) and `findings["failure_category"]` (one of: incompatible_payload, version_mismatch, config_problem, writable_path_missing, wrong_targeturi, network_refused, generic).
3. In `_replan_from`, the FAILED entries in the `REMAINING NODES` dict already include `failure_reason` (currently the summary). Augment with `failure_cause` and `failure_category` so the LLM sees specifics.
4. Update prompt rule: "When a previous attempt failed with `failure_category=writable_path_missing`, try a different SITEPATH or a different module entirely."

**Correctness check (offline):** `experiments/test_stage_c_failure_causes.py`
- Feed each known failure-pattern MSF output to `_parse_msf_output`.
- Assert `failure_cause` and `failure_category` are correctly tagged.
- Assert generic failures (no known pattern) get `failure_category="generic"`.

**Live test:** Re-run `live_test_fix_1.py`. Pass criteria:
- Failed proftpd_modcopy_exec node has `failure_category="writable_path_missing"`.
- Failed rails_secret_deserialization has `failure_category="wrong_targeturi"`.
- Replanner's subsequent proposal differs in proportion to the cause (e.g. doesn't blindly retry the same vector).

**Risk:** Low-medium. Adds parsing complexity. If a pattern is over-broad, we mis-categorise — but worst case the LLM ignores the wrong tag.
**Rollback:** Revert `_parse_msf_output` changes + the context augmentation.

---

### Stage D — Fix the LHOST=127.0.0.1 silent default

**Goal:** Ensure LHOST/LPORT actually reach the MSF console when the replanner proposes a module without specifying a payload. This is a real bug — `payload_options.LHOST` is being set on the node but never `set` in the console because `_execute_msf_module` gates that on `effective_payload` being non-empty.

**Code delta** (`core_agents/orchestrator.py`, lines ~329-336):
Today:
```python
cmds = [f"use {node.module}"]
for k, v in effective_module_options.items():
    cmds.append(f"set {k} {v}")
if effective_payload:
    cmds.append(f"set PAYLOAD {effective_payload}")
    for k, v in effective_payload_options.items():
        cmds.append(f"set {k} {v}")
cmds.append("run")
```
Change to: emit `set LHOST` / `set LPORT` from `payload_options` **even when no payload is explicitly set**. MSF will apply them to whatever default payload the module chooses.
```python
cmds = [f"use {node.module}"]
for k, v in effective_module_options.items():
    cmds.append(f"set {k} {v}")
if effective_payload:
    cmds.append(f"set PAYLOAD {effective_payload}")
# Always set LHOST/LPORT from payload_options so the default payload picks them up
for k, v in effective_payload_options.items():
    cmds.append(f"set {k} {v}")
cmds.append("run")
```

**Correctness check (offline):** `experiments/test_stage_d_lhost.py`
- Build a node with `module=foo`, `payload=""`, `payload_options={"LHOST": "10.0.0.1", "LPORT": 4444}`.
- Mock `msf_session.send_command` to record commands.
- Assert `set LHOST 10.0.0.1` and `set LPORT 4444` appear in the captured commands.

**Live test:** Re-run `live_test_fix_1.py`. Pass criteria:
- Zero `binding to a loopback address` warnings.
- Any reverse-shell payload uses our real attacker IP, visible in the log.

**Risk:** Very low — it's a one-line move. The behavior only changes for nodes with `payload_options` set but no explicit `payload` (which today silently misconfigures).
**Rollback:** Move the `for k, v in effective_payload_options.items()` block back inside the `if`.

---

## Sequencing & dependencies

| Order | Stage | Risk | Why this position |
|---|---|---|---|
| 1 | D — Fix LHOST default | very low | One-line bug; fixes a definite defect; standalone |
| 2 | A — MSF catalog validation | low | Single helper + one rejection point; kills hallucination |
| 3 | B — Privilege extraction | low | Pure info addition; helps replanner make better choices |
| 4 | C — Failure cause tagging | low-medium | Most parsing work; builds on B's findings shape |

D is the cheapest real win (a literal bug). A is the highest-impact accuracy win (kills 20% of all proposals). B and C are quality-of-context improvements that compound with A.

## Open questions to resolve before implementing

1. **Catalog query cost.** Need to confirm `client.modules.exploits` returns a complete list in reasonable time. If it's slow, accept the one-time cost; if it's stale, accept the rare false reject. We don't need rare modules.
2. **What about `auxiliary` / `post` / `payload` modules?** Replanner today only proposes exploits. If we extend later, need to grow the catalog set.
3. **Privilege parsing format variance.** Different shells / OSes emit `uid=`/`groups=` in different orders. Sample more outputs (or just be liberal in parsing).
4. **Should category-aware judge prompting be part of Stage C, or its own stage E?** Defer until C lands and we see whether the LLM uses the info.

## What this plan does NOT address

- **LLM model upgrade.** gpt-4o-mini is the bottleneck for instruction-following ("DO NOT repeat" ignored). Upgrading to gpt-4o would help but isn't a code fix. Tracked separately as a config option.
- **Replanner reflecting on its own past proposals across runs.** Today each run starts fresh; we don't carry over "we tried X on this target last week." Future work.
- **Stage subagents (recon/exploit/persistence) and their internal logic.** Some bad LHOST settings may originate in `stages/initial_access.py`'s LLM-driven exploit selection. That's a separate refactor — out of scope.
