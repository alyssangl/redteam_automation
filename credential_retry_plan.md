# Credential-Retry & Anti-Repeat Refinement Plan

Companion to `replanner_reliability_plan.md`. Captures a specific replanner blind spot surfaced by the `init_fail` live test on 2026-05-21.

---

## How to resume this next session

1. **Confirm where the branch is.** `git log --oneline -5` should show `6bb5ead` (pipeline journey report) at the top. Branch is `graph-orchestrator`.
2. **Re-read the diagnosis below** (it's short). The key insight: when `ssh_bruteforce(root/root)` fails, the LLM doesn't propose `ssh_login(vagrant/vagrant)` even though the graph's OBJECTIVE explicitly says "use vagrant." Three coupled reasons; see below.
3. **Run the failing fixture once to confirm same behavior** (~10 min): `PYTHONIOENCODING=utf-8 python experiments/live_test_init_fail.py`. Look at the resulting `logs/init_fail_*.log` — expect 14% success rate (only `recon` succeeds), with the replanner proposing alt exploit vectors instead of alt SSH credentials.
4. **Start with Stage W**, it's the smallest unblock and the others build on it. See order below.

---

## Diagnosis (what the init_fail run showed)

Log: `logs/init_fail_192.168.34.7_20260521_164929.log`. Replanner activated 4 times, picked alternative exploit vectors every time (proftpd_modcopy_exec → usermap_script → unreal_ircd_3281_backdoor → phpmyadmin_pma). None worked because MS3 doesn't have those specific vulnerabilities. The LLM never proposed retrying SSH with `vagrant/vagrant`, even though:

- The graph's `OBJECTIVE` text literally contains: *"Initial credentials are root/root which WILL NOT work on this Metasploitable 3 target. The replanner must find an alternative."* — and this WAS in the replanner's context (verified by grep).
- vagrant/vagrant is widely known on Metasploitable 3 — gpt-4o certainly knows this from training data.

So why didn't it try? Three coupled bugs:

### Bug 1 — anti-repeat guard silently blocks "same module, different options"

Stage 4 v3's anti-repeat guard rejects any proposal whose `module` matches a FAILED node's module. After `ssh_bruteforce(root/root)` fails, the failed node has `module=auxiliary/scanner/ssh/ssh_login`. If the LLM proposes `{"action": "use_module", "target_hint": "auxiliary/scanner/ssh/ssh_login", ...}` intending to swap credentials, the guard rejects it as a repeat. The LLM has no way to express "same module, different params."

Code: `core_agents/orchestrator.py:_replan_from` — the `if failed_with_same_module:` block.

### Bug 2 — tiny-intent schema has no slot for `module_options`

Stage 4's intent schema is `{action, target_hint, label?, goal?, rationale}`. There's no field for `module_options`. `_expand_intent_to_node` fills in fixed defaults (`RHOSTS=target_ip`, `LHOST=attacker_ip`, `LPORT=4444`). USERNAME/PASSWORD are never set by the expander — so even if the LLM tried `ssh_login` again, the expanded node would have empty credentials and run nothing useful.

Code: `core_agents/orchestrator.py:_expand_intent_to_node`.

### Bug 3 — Stage C lumps "no credentials found" into `generic`

`_classify_msf_failure` doesn't have a pattern for `"no credentials found"` / `"Authentication failed"`. Auxiliary scanner failures tag as `generic`, giving the LLM no specific signal that the failure was credential-related (vs. version-mismatch / wrong path / network).

Code: `core_agents/orchestrator.py:_MSF_FAILURE_PATTERNS`.

---

## Plan: four small stages

### Stage W — Anti-repeat compares (module + options), not just module

**Goal:** Allow the LLM to legitimately retry the same module with different options. Block only when both the module AND the discriminating options match a failed node.

**Code delta** (`core_agents/orchestrator.py`, the `_replan_from` guard around line ~1545):

Replace:
```python
failed_with_same_module = [
    n.id for n in graph.nodes.values()
    if n.status == NodeStatus.FAILED.value and n.module == new_node.module
]
if failed_with_same_module:
    log.warning(f"[Replanner] REJECTED {new_node.module}: already tried "
                f"and failed in {failed_with_same_module}")
    return None
```

With a key-based comparison. Define a small helper:
```python
def _config_key(module: str, options: dict) -> tuple:
    """Stable tuple of (module, sorted-options) for repeat detection."""
    return (module, tuple(sorted((str(k), str(v)) for k, v in (options or {}).items())))
```

Then:
```python
new_key = _config_key(new_node.module, new_node.module_options)
failed_with_same_config = [
    n.id for n in graph.nodes.values()
    if n.status == NodeStatus.FAILED.value
    and n.module == new_node.module
    and _config_key(n.module, n.module_options) == new_key
]
if failed_with_same_config:
    log.warning(
        f"[Replanner] REJECTED {new_node.module} with same options: "
        f"already tried and failed in {failed_with_same_config}"
    )
    return None
```

**Correctness check (offline):** `experiments/test_stage_w_anti_repeat_key.py`
- Build graph with FAILED `ssh_login` having `module_options={USERNAME:root, PASSWORD:root}`.
- Propose `ssh_login` with `module_options={USERNAME:vagrant, PASSWORD:vagrant}` — assert ACCEPT.
- Propose `ssh_login` with same `{root, root}` — assert REJECT.
- Propose totally different module with no options — assert ACCEPT.

**Live test:** `experiments/live_test_init_fail.py`. Pass criterion: at least one replan proposes `auxiliary/scanner/ssh/ssh_login` with NON-root credentials and the proposal is NOT silently rejected. (May still fail in MSF if creds wrong, but that's a different signal.)

**Risk:** Low. Loosening, not tightening. Worst case: LLM proposes legitimate-looking variations more often, slightly more retries.

### Stage X — Extend tiny-intent to allow `module_options` (and `payload_options`)

**Goal:** Give the LLM a way to express specific module configuration when retrying. Backward-compatible — absence of these fields means defaults (unchanged behavior).

**Code delta:**

1. Update `REPLAN_PROMPT` (`core_agents/orchestrator.py` around line ~1340). Add a new sub-shape:
```json
{
  "action": "use_module",
  "target_hint": "auxiliary/scanner/ssh/ssh_login",
  "module_options": {"USERNAME": "vagrant", "PASSWORD": "vagrant"},
  "rationale": "root/root failed; try the common Metasploitable creds"
}
```
   And mention it as the natural pivot for `failure_category=credentials_failed` (defined in Stage Z below).

2. Update `_expand_intent_to_node` to merge intent's `module_options` over the defaults:
```python
default_module_options = {"RHOSTS": graph.target_ip}
rport = _guess_rport_from_module(target_hint)
if rport: default_module_options["RPORT"] = rport
# NEW: intent's module_options take precedence over defaults
module_options = {**default_module_options, **intent.get("module_options", {})}
```
   Same pattern for `payload_options`.

**Correctness check (offline):** `experiments/test_stage_x_intent_options.py`
- Intent with `module_options.USERNAME=vagrant` → expanded node has `RHOSTS=target_ip` (default kept) AND `USERNAME=vagrant` (override applied).
- Intent without `module_options` → expanded node has only the defaults (unchanged behavior).
- Intent with conflicting `RHOSTS` override → intent wins (intentional — LLM may know better).

**Live test:** init_fail. Pass: at least one replan emits `module_options.USERNAME` and the expanded node correctly carries it into MSF (`set USERNAME vagrant` visible in log).

**Risk:** Low. Additive field.

### Stage Z — Add `credentials_failed` failure category

**Goal:** Stage C currently tags credential-style failures as `generic`. Adding a specific tag lets the prompt rule from Stage Y trigger on it.

**Code delta** (`core_agents/orchestrator.py:_MSF_FAILURE_PATTERNS`, add as one of the earlier entries to win over `generic`):

```python
(re.compile(r"no credentials found|Authentication failed|Login failed|"
            r"All login attempts failed",
            re.IGNORECASE), "credentials_failed"),
```

**Correctness check (offline):** add to `experiments/test_stage_c_failure_causes.py`:
- Output `"[*] Bruteforce complete -- no credentials found"` → category `credentials_failed`.
- Output `"Authentication failed for user root"` → category `credentials_failed`.

**Live test:** init_fail. Pass: FAILED ssh_bruteforce entry in replanner's REMAINING NODES shows `failure_category: "credentials_failed"`.

**Risk:** Very low (one regex line).

### Stage Y — Prompt nudge for credential alternatives

**Goal:** Bias the LLM toward credential variation BEFORE switching attack vectors, when the failure was credential-related.

**Code delta** (`REPLAN_PROMPT`, add a Rules bullet):
```
- *** If REMAINING NODES contains a FAILED node with
    failure_category=credentials_failed, STRONGLY PREFER retrying the same
    module with different credentials over switching to a new attack vector.
    Common Metasploitable / lab credentials to try (one per replan):
    vagrant/vagrant, msfadmin/msfadmin, admin/admin, root/toor, ubuntu/ubuntu.
    Express this via Stage 2.5 (use_module with module_options.USERNAME and
    .PASSWORD set).
```

**Live test:** init_fail. Pass: after `ssh_bruteforce(root/root)` fails, the FIRST replanner proposal targets `ssh_login` with non-root credentials (vagrant or msfadmin), and an SSH session opens.

**Risk:** Low (prompt-only). Reversible.

---

## Sequencing (order I'd implement)

| Order | Stage | Why this position |
|---|---|---|
| 1 | **W** — anti-repeat key refinement | Currently silently blocking valid proposals. Without W, X+Y can't take effect. |
| 2 | **X** — intent extension for module_options | Gives the LLM a way to express what Y tells it to do. |
| 3 | **Z** — credentials_failed category | One regex; sets up Y's trigger. |
| 4 | **Y** — prompt nudge | The actual behavior change. Cheapest to revert if it backfires. |

All four are small (~20–60 lines each). Total commit count: 4 (one per stage, same pattern as the prior plans).

---

## Verification arc

Two live runs on `experiments/live_test_init_fail.py`:

| Run | Setup | Expected |
|---|---|---|
| 1 | Baseline (current state, no stages from this plan) | Same as 16:49:29 run: ~14% success, 4 failed exploit proposals, no SSH credential retry attempts |
| 2 | After W+X+Z+Y all landed | LLM proposes `ssh_login(vagrant/vagrant)` early; SSH session opens; `privesc_verify` and `file_drop` run on top of the new session; `/tmp/pwned.txt` actually gets written; success rate ≥ 4/4 |

If run 2 doesn't reach `file_drop`, that's a separate concern (probably the goal-coverage gap addressed by a different plan).

---

## Open questions to resolve before implementing

1. **How many credential pairs to suggest in the prompt?** Five (vagrant, msfadmin, admin, root/toor, ubuntu) keeps it short; could be expanded. More = more replan attempts before giving up.
2. **Should Stage X also accept `command_params` overrides for `run_commands` intents?** Probably yes (symmetric with module_options) — same pattern, cheap to add. Decide before implementing X.
3. **Strict failure-category matching in Y's rule, or fuzzy "credentials in label/goal" too?** Strict is simpler; might miss cases where Stage Z doesn't fire. Recommend: strict for now, expand later if needed.

---

## Related but separate work

Two other concerns are tracked elsewhere and are NOT addressed by this plan:

1. **Goal-coverage skip** — replanner uses `new_edge` to skip past planned nodes whose goals aren't yet covered (e.g., skipping `persistence` to reach `disk_wipe`). Different architectural issue. The user prioritized this above credential-retry; consider doing it first or in parallel.

2. **`disk_wipe_graph.py`'s `persistence` node has a broken hardcoded MSF module path** (`exploit/linux/local/service_persistence` doesn't exist). Graph defect, not orchestrator. Fix the graph or remove that node.
