# Judge Redesign — Implementation Plan

Companion to `Lessons from VulnBot.pdf`. Stages are ordered by risk and reversibility — earliest changes are the smallest and most reversible.

Each stage has:
- **Goal** — what changes and why
- **Code delta** — exact files and lines
- **Correctness check** — offline (no Kali needed) assertions
- **Live test** — end-to-end against Metasploitable 3
- **Risk / rollback**

Testing convention: stage `N` lives in `experiments/test_stage_N.py`. Each is a standalone script that builds a minimal `AttackGraph` in memory, monkey-patches `call_llm` where needed, and asserts on results. No formal test framework — just `assert` statements with clear messages. Run with `python experiments/test_stage_N.py`.

---

## Stage 1 — Demote `MSF_MODULE_REQUIREMENTS` to advisory

### Goal
Stop hard-rejecting replanner proposals on version mismatch. The PDF's argument: failure is signal — gating preempts it. A proposal that *might* work should be allowed to run and fail naturally; the failure output then feeds the next replan.

This reverses the recent commit `cbaa9bf` from a blocker into a warning. Keep the table — the *log line* is still useful guidance for the LLM next time around.

### Code delta
File: `core_agents/orchestrator.py`

1. `_replan_from`, lines 1058-1073 — change reject to advisory:
   ```python
   # BEFORE
   if not ok:
       log.warning(f"[Replanner] REJECTED proposal {proposed_module}: {reason}")
       return None
   log.info(f"[Replanner] Module validation OK: {reason}")
   edge_checks = _build_msf_module_checks(proposed_module)

   # AFTER
   if not ok:
       log.warning(f"[Replanner] ADVISORY mismatch for {proposed_module}: {reason} — allowing anyway")
   else:
       log.info(f"[Replanner] Module validation OK: {reason}")
   # edge_checks stays empty — do not persist hard checks
   ```

2. Leave `MSF_MODULE_REQUIREMENTS`, `_validate_msf_module_for_target`, and `_build_msf_module_checks` in place. They become diagnostic helpers, not gates. (We may delete `_build_msf_module_checks` in Stage 4 if it's truly unused — defer that decision.)

### Correctness check (offline)
`experiments/test_stage_1.py`:
- Build a graph with one SUCCESS recon node whose `findings.ports` says `ProFTPD 1.3.5`.
- Monkey-patch `call_llm` to return a proposal for `exploit/unix/ftp/proftpd_133c_backdoor` (version mismatch — 1.3.5 vs required 1.3.3c).
- Call `_replan_from(graph, recon_id, log)`.
- **Assert**: return value is a new node id (not `None`).
- **Assert**: a new edge `recon → <new_id>` exists with `checks == []` (no persisted version block).
- **Assert**: log captured contains "ADVISORY mismatch".

### Live test
Run `python -m core_agents.orchestrator examples/disk_wipe_graph.json` with `explore=True` against Metasploitable 3. Force a stuck state (e.g. break the SSH edge check). Observe in the log that replanner proposals are no longer rejected for version reasons. Run finishes with at least one replanner-issued node executed (success or fail both acceptable — we're measuring that it *attempted*).

### Risk / rollback
**Low.** We're loosening, not tightening. Worst case: more failed runtime attempts (which is the entire point — that's the signal we want). Rollback is a one-line revert.

---

## Stage 2 — Feed prose into the replan context

### Goal
The replanner currently reasons from a stripped structured summary. Give it what an operator would read: full nmap output and the last few raw command outputs. This is "Context" in the PDF's five-cause list.

### Code delta
File: `core_agents/orchestrator.py`

1. Lines 944-945 — stop stripping `raw_nmap_output`. Pass `stuck_node.findings` through:
   ```python
   # BEFORE
   trimmed_findings = {k: v for k, v in stuck_node.findings.items()
                       if k != "raw_nmap_output"}
   # AFTER
   trimmed_findings = dict(stuck_node.findings)  # keep everything
   ```
   (If `raw_nmap_output` ever causes context overflow, cap it at 8 KB rather than dropping it. Add `_cap(s, 8192)` helper.)

2. Add a helper to surface recent command output:
   ```python
   def _recent_command_excerpts(node: AttackNode, n: int = 3, cap: int = 2048) -> list[dict]:
       """Last n CommandRecord entries, output capped at `cap` chars."""
       out = []
       for rec in node.commands[-n:]:
           out.append({
               "command": rec.command,
               "tool": rec.tool,
               "exit_code": rec.exit_code,
               "output_tail": (rec.output or "")[-cap:],
           })
       return out
   ```

3. Inject into the context string (after the `FAILED OUTGOING EDGES` block, around line 1005):
   ```python
   recent_cmds = _recent_command_excerpts(stuck_node)
   context += (
       f"\nRECENT COMMAND OUTPUT (last 3, tails):\n"
       f"{json.dumps(recent_cmds, indent=2, default=str)}\n"
   )
   ```

### Correctness check (offline)
`experiments/test_stage_2.py`:
- Build a node with `findings={"raw_nmap_output": "PORT 21/tcp ProFTPD 1.3.5", "ports": [...]}` and 4 `CommandRecord` entries with distinct outputs.
- Capture the context string by monkey-patching `call_llm` to a stub that records `messages[0].content` and returns a `give_up` proposal.
- **Assert**: captured context contains `"ProFTPD 1.3.5"` (raw nmap preserved).
- **Assert**: captured context contains the last 3 command outputs but not the first one.
- **Assert**: each `output_tail` is ≤ 2048 chars.

### Live test
Same Metasploitable 3 run as Stage 1. Inspect the log when `_replan_from` fires — the printed context should now include the nmap dump and the last 3 commands. No behavior change required; this stage is about *what the LLM sees*.

### Risk / rollback
**Low.** Additive — we're sending more tokens to the replanner LLM. The only real risk is context-window blowout on huge nmap outputs; the 8 KB cap handles that. Rollback: revert the helper + restore the strip.

---

## Stage 3 — Add `judge()` and rewire the retry loop

### Goal
The central change. Insert a layer-2 decision function between the executor and the replanner, called at three trigger points. This is what makes cadence and sequencing fixable.

The judge is a small LLM call (~200 tokens in, ~50 out) that emits one of three decisions:
- `continue` — keep going on the current path (default; cheap)
- `adapt` — current node should retry with a different parameter (use existing `*_alternatives`)
- `escalate` — this approach is dead, call the replanner now

The judge replaces the rigid "exhaust max_retries then backtrack" logic with judgment about whether more retries will help.

### Code delta
File: `core_agents/orchestrator.py`

1. New function `judge(...)` — pure LLM call returning a parsed decision dict:
   ```python
   JUDGE_PROMPT = """You are a step-by-step strategic judge for an autonomous pentest.
   After each node attempt, decide what to do NEXT.

   Return JSON: {"action": "continue" | "adapt" | "escalate", "hint": "..."}

   Choose:
     continue — node succeeded, or failure is transient (timeout, race). Proceed.
     adapt    — node failed, but a parameter tweak (alt payload / path) might fix it.
                Only valid if `alternatives_remaining` > 0.
     escalate — this approach is dead. Call the replanner; don't waste more retries.

   Hint is one sentence guiding the next action."""

   def judge(
       trigger: str,                    # "post_retry" | "post_node" | "pre_replan"
       node: AttackNode,
       graph: AttackGraph,
       log: logging.Logger,
   ) -> dict:
       """One LLM call. Returns {'action': str, 'hint': str}."""
       context = _build_judge_context(trigger, node, graph)
       try:
           resp = call_llm(messages=[HumanMessage(content=context)],
                           system_prompt=JUDGE_PROMPT)
           result = parse_json_response(resp.content)
       except Exception as e:
           log.warning(f"[Judge] LLM call failed ({e}) — defaulting to continue")
           return {"action": "continue", "hint": ""}
       action = result.get("action", "continue")
       if action not in ("continue", "adapt", "escalate"):
           action = "continue"
       return {"action": action, "hint": result.get("hint", "")}
   ```

   `_build_judge_context` is a small helper that packages: trigger reason, node id/label/status, last command output tail (reuse `_recent_command_excerpts` from Stage 2), remaining alternatives count, available outgoing edges.

2. Refactor `_execute_node` (current lines 1155-1215) — replace the unconditional retry loop:
   ```python
   while True:
       node.mark_running()
       findings = dispatch_node(node, graph, log, explore=explore)
       success = findings.get("success", False)

       if success:
           node.mark_success(findings, findings.get("summary", ""))
           _checkpoint(graph, checkpoint_path, log)
           return True, "success"

       node.mark_failed(findings.get("summary", "unknown"))
       if not node.can_retry:
           return False, "retries_exhausted"

       # NEW: consult judge instead of always retrying
       decision = judge("post_retry", node, graph, log)
       log.info(f"  [{node.id}] Judge says: {decision['action']} — {decision['hint']}")

       if decision["action"] == "escalate":
           return False, "judge_escalate"
       # 'adapt' and 'continue' both retry; 'adapt' lets dispatch_node pick
       # the next alts[] entry (that already happens via node.retries counter).
       time.sleep(2)
   ```

   Return tuple `(success: bool, reason: str)` so the walker can distinguish "retries exhausted" from "judge escalated early".

3. Wire judge into `run_graph` (around line 1331, after node executes successfully):
   ```python
   if success:
       # NEW: post-node judge call (cheap)
       decision = judge("post_node", node, graph, log)
       if decision["action"] == "escalate":
           # Skip outgoing-edge evaluation, go straight to replanner
           needs_replan = True
           # ... existing replanner block
   ```

4. Add `use_judge: bool = True` as a `run_graph` parameter. When `False`, all judge calls return `{"action": "continue"}` — restores old behavior. This is our A/B switch.

### Correctness check (offline)
`experiments/test_stage_3.py`:
- **Judge unit**: build 3 synthetic contexts (a clear failure, a transient timeout, a success). Monkey-patch `call_llm` to return canned responses. Assert each maps to the right action.
- **Retry-loop integration**: build a node with `max_retries=3` whose `dispatch_node` returns failure. Patch judge to return `escalate` on the first call. Assert `_execute_node` returns `(False, "judge_escalate")` after only **one** attempt — not three.
- **Backwards-compat**: same setup with `use_judge=False`. Assert it runs the full 3 retries.
- **Walker post-node**: build a 2-node graph where node A succeeds. Patch judge to return `escalate` on `post_node`. Assert the walker calls `_replan_from` instead of evaluating A's outgoing edges.

### Live test
Two runs against Metasploitable 3:
1. `use_judge=False` — baseline. Record total nodes attempted, total replan calls, wall time.
2. `use_judge=True` — same graph. **Expect**: fewer total node attempts (judge cuts dead-end retries short), more replan calls *earlier*, similar or better final success rate. The win is faster failure recognition, not necessarily better end state.

Concrete success criterion: on a graph where node X is known to be unfixable by retries, judge should escalate before retry 3 in at least one run.

### Risk / rollback
**Medium-large.** Touches the hot loop. The `use_judge` flag gives us a clean kill-switch. Rollback path: flip the default, then revert at leisure.

Additional risk: the judge LLM call adds latency to every node attempt (~1-2s). Mitigation: it only fires on failures (`post_retry`) and once per node completion (`post_node`). Cost is bounded by node count, not retry count.

---

## Stage 4 — Lower the emission bar

### Goal
Stop asking the replanner LLM to emit 15 nested fields. Have it emit `{action, target, hint}` and let code expand to a full `AttackNode` using defaults derived from `graph.attacker_ip`, `graph.target_ip`, recon findings, and known MSF module shapes.

This is the highest-disruption change. Defer until Stages 1-3 land — the judge from Stage 3 can compensate when expansion picks suboptimal defaults.

### Code delta
File: `core_agents/orchestrator.py`

1. Rewrite `REPLAN_PROMPT` (lines 819-928). New schema:
   ```json
   {
     "action": "use_module" | "run_commands" | "new_edge" | "give_up",
     "target_hint": "exploit/unix/ftp/proftpd_modcopy_exec"
                    OR "/etc/init.d/cron + crontab line"
                    OR "existing_node_id",
     "rationale": "..."
   }
   ```

2. New expander `_expand_intent_to_node(intent, graph, stuck_node) → AttackNode`:
   - For `use_module`: derive `module_options.RHOSTS=graph.target_ip`, `payload_options.LHOST=graph.attacker_ip`, default `LPORT=4444`, infer `service`/`port` from the module name via MSF_MODULE_REQUIREMENTS hint table.
   - For `run_commands`: split the freeform string into `commands_to_run`, default `tool_name="session"` (if predecessor has a session) or `"ssh"` (Kali-side).
   - Always fill `agent_type` by routing on intent kind.

3. Replace the giant `new_node` branch in `_replan_from` (lines 1049-1107) with:
   ```python
   intent = result  # already parsed
   new_node = _expand_intent_to_node(intent, graph, stuck_node)
   if not new_node:
       return None
   graph.add_node(new_node)
   graph.connect(stuck_node_id, new_node.id, ...)
   return new_node.id
   ```

### Correctness check (offline)
`experiments/test_stage_4.py`:
- Mock `call_llm` to return tiny intents for each `action` kind.
- For each, call `_replan_from` and assert the resulting `AttackNode`:
  - Has all required fields populated (`id`, `agent_type`, `target_ip`, `tool_name`).
  - For `use_module`: `module_options.RHOSTS == graph.target_ip`, `payload_options.LHOST == graph.attacker_ip`.
  - For `run_commands`: `commands_to_run` is non-empty list.

### Live test
End-to-end Metasploitable 3 run. **Success criterion**: at least one replanner-issued node from a tiny intent reaches `SUCCESS` status. Compare replanner-emit token count to baseline — expect ~5× reduction in completion tokens per replan call.

### Risk / rollback
**Medium.** The expander is a new surface area that can guess wrong. Keep the old `REPLAN_PROMPT` + `new_node` branch behind a flag (`emit_intent_only: bool = True`) for one or two cycles, so we can compare quality. Drop the old branch once we trust expansion.

---

## Sequencing summary

| Order | Stage | Risk | Why now |
|---|---|---|---|
| 1 | Advisory gate | low | Reverses last week's overreach in one edit |
| 2 | Richer context | low | Improves every downstream call; pure addition |
| 3 | Judge + retry rewire | med-large | The actual architecture change |
| 4 | Lower emission bar | medium | Best done after judge can correct for it |

Stages 1 and 2 are independent and could ship as one PR. Stage 3 is the largest. Stage 4 is gated on Stage 3 landing cleanly.

## Decisions (locked in)

1. **Judge model**: `gpt-4o-mini` (matches `common.py:24` default).
2. **Replan budget**: raise `max_replan_attempts` from 5 → 10 (`orchestrator.py:1260`). Done as part of Stage 3 where it's load-bearing.
3. **Judge context**: minimal — current node + last 3 commands + remaining edge count. No global graph summary.
