# HANDOFF — lgg_automation

**For the next engineer.** This is the one doc to read first. It captures the
mental model, the lab operations, the landmines, and the roadmap — the stuff that
*isn't* obvious from the code or git history. Everything here is verified against
the code as of 2026-07-01 on branch `graph-orchestrator`.

> **If you read nothing else:** the real code is `core_agents/orchestrator.py` +
> `stages/*.py`, NOT `single_focus.py` (that's dead, now under `legacy_agents/`).
> `CLAUDE.md` is partly stale — trust this doc and the file:line refs below.
> The current work lives on branch **`graph-orchestrator`** (~20 commits ahead of
> `master`, **not merged**). Nothing is in production; this is a lab research tool.

---

## 0. Orientation — current state in one screen

- **What it is:** an autonomous red-team pipeline. You hand it an *attack graph*
  (nodes = actions, edges = decisions) and a target; it walks the graph, driving
  Metasploit + SSH against a lab machine, backtracking and re-planning when stuck.
- **Where it runs:** a controlled lab — **Kali attacker `192.168.34.6`**,
  **Metasploitable 3 (Linux) target `192.168.34.7`**. Never point it at anything
  you don't own.
- **Branch:** `graph-orchestrator`. The last big push was the v16–v19 subagent
  refinement batch (privesc kernel path, initial_access proven-vector bias,
  credential-retry rotation). All offline-tested; **live validation still owed**
  (the lab was down at handoff — see §4).
- **The evolution story** (why the code looks the way it does) is in
  `reports/refinement_history_v0_v19.md`. Read it after this.

---

## 1. The killchain

Five stages, each a self-contained LangGraph subagent under `stages/`:

```
recon → initial_access → privesc → persistence → impact
(scan)   (get a session)  (get root) (stay in)   (do the objective)
```

The orchestrator doesn't have to run them linearly — the *graph* decides the
shape, and the walker/replanner can branch, skip, backtrack, and grow new nodes.

---

## 2. Mental model — how it actually works

### 2.1 The graph (`core_agents/attack_graph.py`)

- **`AttackNode`** — one action. Carries `agent_type` (recon/exploit/privesc/
  persistence/impact), a `goal`/`objective`, and *optionally* a concrete `module`
  + `module_options`/`payload_options`, or `commands_to_run` + `command_params`.
- **`AttackEdge`** — a decision. Carries a `condition` (ON_SUCCESS/…) and
  `checks` (`EdgeCheck(field, operator, ...)`, e.g. "session_id exists") plus
  human-readable `reasoning`.
- Graphs are **serializable to JSON** and **checkpointed** to `graphs/` after
  each node, so an interrupted run resumes instead of restarting.
- You define graphs in `examples/*.py` via `build_*_graph(target_ip, attacker_ip)`.

### 2.2 The walker (`core_agents/orchestrator.py:run_graph`, line ~2034)

`run_graph(graph, checkpoint_path=None, explore=False, use_judge=True)`.
A **backtracking walker**: follow one path forward; on node failure, mark the
edge tried, backtrack to the predecessor, and (in explore mode) hand off to the
replanner. `ready_nodes()` uses `all()` over incoming edges, so the replanner can
unblock a node by removing/adding edges.

### 2.3 ⭐ The single most important fact: direct path vs subagent path

Inside `_execute_node` (orchestrator.py ~177 vs ~202) there is a fork:

- **Direct path (no LLM):** if a node carries a `module`/`commands_to_run`, the
  orchestrator runs it straight over MSF/SSH. Fast, deterministic, cheap.
- **Subagent path (LLM):** if a node is **goal-only** (no module/commands) — or,
  since commit `e0e350a`, a direct node whose execution *failed* while
  `explore=True` — it dispatches to the stage subagent (`run_recon`,
  `run_exploitation`, `run_privesc`, …) which improvises within its scope.

**Consequence for testing:** a graph full of prescribed modules (e.g.
`examples/continuum_rce_graph.py`) mostly exercises the *direct path* and only
`recon` as a subagent. To actually test the exploit/privesc/persistence/impact
**subagents**, use a **goal-only** graph (`examples/goal_only_graph.py`) or a
**flawed** graph (`examples/flaw_*_graph.py`, one broken stage each). If you
"refined a subagent" and nothing changed at runtime, you were probably on the
direct path — check the logs for `[direct]` vs `[Dispatch]`.

### 2.4 The 3-layer model (from `Lessons from VulnBot.pdf`)

The pipeline is organized as three layers of decision-making — internalize this,
it's the design north star:

- **L1 Tactical** — the stage subagents (`stages/*.py`). Each is its own
  Planner→Executor→Critic (some add Enumerator/Verifier/Researcher) ReAct loop.
  *Design rule: tight kill-chain scope, but broad tools/prompts inside that scope*
  (don't let a stage plan/orchestrate, but don't starve it of capability either).
- **L2 Strategic** — `judge()` in orchestrator.py. Runs after a failed retry / a
  node completes; emits `continue | adapt | escalate`. Catches drift early so L3
  fires less. `adapt` can rewrite a failing command via the LLM
  (`_rewrite_commands_with_hint`).
- **L3 Heavyweight** — `_replan_from()` (orchestrator.py ~1595). Graph mutation.
  The LLM emits a **tiny intent** `{action, target_hint, module_options?, …}` and
  code (`_expand_intent_to_node`) expands it into a full node. Guards:
  anti-repeat by `_config_key(module, options)`, MSF-catalog validation
  (`_module_exists_in_msf`), dead-node rejection, `new_edge` skip-connect to
  ready planned nodes.

### 2.5 How findings/sessions flow between stages

- Each stage returns a `Findings` TypedDict (`core_agents/state.py`):
  `ReconFindings`, `ExploitationFindings`, `PrivEscFindings`, etc.
- Downstream nodes read predecessors via `graph.gather_preceding_findings(node_id)`
  — **direct predecessors only**, not all ancestors.
- `_find_session(preceding)` picks the session to hand a stage. As of v16b it
  prefers the **most-escalated** successful session (root > sudo > user), so a
  privesc-upgraded root session reaches `impact` instead of the original shell.
- **Gotcha that bit us repeatedly:** if a stage doesn't put `session_id` in its
  findings, the session silently doesn't propagate. `PrivEscFindings` had this bug
  until v16b.

---

## 3. The five subagents (`stages/`)

Each is a compiled LangGraph with internal roles and its own prompts. Common
shape: a Planner picks an approach, an Executor runs it (ReAct with MSF/SSH
tools), a Critic grounds success on **real tool output**, not the LLM's prose.

| Stage | File | Internal roles | Watch for |
|---|---|---|---|
| recon | `recon.py` | Planner→Executor→Critic | force-routed to subagent; top-ports-first (never `-p-`); catches `GraphRecursionError` |
| initial_access | `initial_access.py` | recon_parser→researcher→planner→parameter_solver→executor→critic | biggest file; `[PROVEN]`-vector bias (v17); 600s time-box; `FAIL_EXHAUSTED` ≠ success |
| privesc | `privesc.py` | Enumerator⟷Planner⟷Executor→Critic | kernel path (v16): upgrade command_shell→meterpreter, then `local_exploit_suggester`/overlayfs/dirtycow; critic uses `getuid` on meterpreter, `id` on shells |
| persistence | `persistence.py` | Planner→Executor→Verifier→Critic | session-type-aware; real pubkeys not placeholders; mandatory FAIL when verification empty |
| impact | `impact.py` | Planner→Executor→Critic | writes + reads-back proof artifacts; `command_params_alternatives` for retries |

**Grounding is sacred.** The recurring #1 bug class was a stage reporting success
it hadn't verified. Every stage's critic runs an independent ground-truth check
(e.g. `id` inside the session) and attaches raw tool output as evidence. Don't
"simplify" that away.

---

## 4. ⭐ The lab (the knowledge that's only in my head)

This is the part you can't get from the code. The lab is the #1 source of
confusing "failures" that are not bugs.

### 4.1 The target reality (Metasploitable 3, Linux, kernel ~3.13)

- Services that matter: **UnrealIRCd 6667**, **Samba 445**, **Apache Continuum
  8080**, **Drupal 80**, **ProFTPD 21/80**. Vagrant user `vagrant/vagrant`.
- **There is NO Jenkins here.** Jenkins is on the *Windows* MS3 image. Port 8484
  is closed; don't chase it.
- **Network RCEs land non-root** (`www-data`/`boba_fett`). The **only reliable
  root path is a kernel local-exploit** — overlayfs (CVE-2015-1328, the cleaner
  one) or DirtyCow (CVE-2016-5195). That's *why* the whole v15/v16 privesc kernel
  work exists.
- Which exploit is "proven" here: **UnrealIRCd** (`unreal_ircd_3281_backdoor`) and
  **ProFTPD** (`proftpd_modcopy_exec`) land reliably; continuum/drupal are flaky.

### 4.2 The confounders (things that look like bugs but are lab state)

1. **Stale msfrpcd = wedged console.** After heavy use, msfrpcd holds stale
   jobs/sessions/handlers and commands start hanging. Symptom in logs: **every
   MSF command taking ~120s** (hitting the wall-clock cap) — e.g. a `set RHOSTS`
   burning 2 minutes. **Always restart msfrpcd between runs.** Helper:
   `experiments/restart_msf.py` (setsid-based reliable restart), or manually
   `msfrpcd -P kali -U kali`.
2. **Kali IP drift (DHCP).** Kali's IP can change on reboot; it's hardcoded in
   several files (see §6). If everything "can't connect," check Kali's actual IP.
3. **Kali eth1 dropping.** The lab NIC sometimes loses its lease → `dhclient eth1`
   then restart msfrpcd.
4. **Flaky UnrealIRCd after heavy use** — a proven vector can start missing;
   restart the target or give it a rest.
5. **Target VM simply off.** If `192.168.34.7` times out on ping *from Kali*
   (`ssh kali@192.168.34.6 'ping -c2 192.168.34.7'`), the target VM is powered
   down — only a human can boot it.

### 4.3 Pre-run runbook (do this before every live run)

```bash
# 1. Is the target up? (ask Kali, it's on the same subnet)
ssh kali@192.168.34.6 'ping -c2 -W2 192.168.34.7'        # 0% loss = up
# 2. Bring up a CLEAN msfrpcd on Kali (clears stale state)
python experiments/restart_msf.py                         # or: ssh kali 'msfrpcd -P kali -U kali'
# 3. Confirm reachability from your box
python - <<'PY'
import socket
for h,p in [("192.168.34.6",55553),("192.168.34.7",80)]:
    s=socket.socket();s.settimeout(3)
    try: s.connect((h,p)); print("OPEN",h,p)
    except Exception as e: print("CLOSED",h,p,e.__class__.__name__)
PY
```

If a run's results look terrible, **check the log for 120s-per-command gaps
before you touch the code** — that's a wedged msfrpcd, not a regression.

---

## 5. How to run everything (verified)

Environment: conda env **`red_teaming_auto_lamgchain`** (Python 3.10). Requires
`.env` with `OPENAI_API_KEY`. Prefix live runs with `PYTHONIOENCODING=utf-8` on
Windows to avoid Unicode console errors.

```bash
# OFFLINE tests (no lab needed — run these constantly, they're your safety net)
python tests/run_offline.py                 # 8 suites / ~52 checks

# LIVE test of one scenario (needs the lab up — see §4.3 first)
python experiments/live_test_continuum.py   # or live_test_proftpd.py, _unrealircd.py, ...
#   -> each builds a graph and calls run_graph(graph, explore=True, use_judge=True)
#   -> watch logs/<scenario>_<ip>_<ts>.log

# The orchestrator directly (CLI)
python -m core_agents.orchestrator examples/continuum_rce_graph.json
python -m core_agents.orchestrator --interactive

# Rebuild the RAG knowledge base (ChromaDB) after changing documents/
python database_utils/build_database.py

# See a stage's internal LangGraph topology
python stages/privesc.py --graph
```

**Debugging a run:** `tail -f logs/<latest>.log`; grep `[Dispatch]` to see which
node routed where; `[direct]` = no-LLM path, `[<Stage> ...]` markers = subagent
turns. `[Replanner]`/`[Judge]` show L3/L2 decisions.

---

## 6. Config to change when the lab moves (file:line)

IPs/creds/models are **hardcoded and duplicated** — grep, don't assume one place.

| What | Value | Where |
|---|---|---|
| Kali/attacker IP | `192.168.34.6` | `core_agents/common.py:25` (`KALI_IP`) — **also** re-declared in `stages/recon.py:42`, `stages/initial_access.py:39`, `legacy_agents/single_focus.py` |
| Kali SSH/MSF creds | `kali`/`kali` | `core_agents/common.py` (`KALI_USER`/`KALI_PASS`) |
| MSF RPC port | `55553` | `core_agents/common.py` |
| Target IP (per scenario) | `192.168.34.7` | every `experiments/live_test_*.py` (top of file) + each `examples/*_graph.py` default arg |
| Replanner/Judge model | `gpt-4o` | `core_agents/orchestrator.py:66-67` |
| Recon model | `gpt-4o` | `stages/recon.py:41` |
| initial_access model | `gpt-4o-mini` | `stages/initial_access.py:38` |
| Default LLM (other stages via `call_llm`) | `gpt-4o-mini` | `core_agents/common.py:24` |
| RAG DB path / embed model | `../databases/...` / `text-embedding-3-small` | `tools/rag.py`, `database_utils/build_database.py` |

> `grep -rn "192\.168\.34\.6" core_agents stages legacy_agents` to find all Kali refs.

**Model note:** replanner+judge were deliberately pinned to **gpt-4o** (was
gpt-4o-mini) — mini hallucinated ~20% of MSF module paths and repeated identical
proposals. If replan quality tanks, that's the first knob. gpt-4o ≈ 10× mini cost.

---

## 7. Landmines (bugs we already paid for — don't reintroduce)

1. **Import-time MSF coupling.** `tools/metasploit_tools.py` used to connect to
   msfrpcd at import, which coupled *every* import to a live lab and made offline
   tests impossible. Fixed to lazy (v8). Offline tests still inject a fake
   `tools.metasploit_tools` into `sys.modules` *before* importing the orchestrator
   — see the top of `tests/test_*` / `experiments/test_stage_a_msf_catalog.py`.
2. **Pair-safe message windows.** OpenAI 400s if a `role:tool` message isn't
   preceded by an assistant `tool_calls`, *and* if a `tool_calls` assistant msg
   isn't followed by a response to **every** id (parallel tool calls). The
   id-aware `_make_pair_safe` (privesc.py) fixes this — slicing a message window
   naively will bring the crash back.
3. **Direct-path false success.** The no-LLM path once counted "ran N commands" as
   success even on "permission denied." It now captures stderr and reads proof
   files back (v13). Any new direct-path logic must verify output, not just run.
4. **Session propagation.** If a stage opens/upgrades a session, it MUST surface
   `session_id`/`session_type` in its findings or the session is orphaned (v16b).
5. **Unbounded tool calls = "why is it so slow."** Every MSF/SSH/session call has
   a wall-clock cap; stages have time-boxes (`PRIVESC_WALLCLOCK_TIMEOUT=300`,
   `EXPLOIT_WALLCLOCK_TIMEOUT=600`). Don't add an unbounded call.

---

## 8. Testing philosophy

**Offline-first.** Almost every bug this project hit was a logic/plumbing bug
found only after a 20–40-min live run. The fix was to make it a 5-second unit
test. `tests/` holds pure-logic checks (no lab); add to them for any new plumbing
and run `tests/run_offline.py` before every commit. Live runs are for *behavior*
validation only (does the LLM actually pivot?), and they need the §4.3 runbook.

**Commit hygiene:** small, self-contained commits (one logical change), so any
piece is revertible. Keep `reports/stage_refinement_cycle_log.md` (per-run
findings) and `reports/refinement_roadmap.md` (future plan) current. This was a
standing request and it kept the history clean.

---

## 9. Roadmap — what I'd do next if I were staying

Full detail in `reports/refinement_roadmap.md`. Priority order:

1. **Live-validate v16–v19** (owed; lab was down at handoff):
   - privesc kernel path actually reaches `uid=0` end-to-end on MS3 (the standing
     gate) — driver: a goal-only/flaw_privesc graph.
   - v17: continuum/drupal fallback pivots to UnrealIRCd instead of time-boxing.
   - v19: `ssh_login(vagrant/vagrant)` proposed after root/root fails —
     `experiments/live_test_init_fail.py`.
2. **Goal-coverage skip** (flagged as the higher-priority architectural gap): the
   replanner uses `new_edge` to skip a planned node (e.g. `persistence`) when a
   later node's *preconditions* are met, but never checks whether the skipped
   node's *goal* is actually covered — so you can wipe the disk without ever
   establishing persistence. `preconditions_met` answers "can it run?", not "is
   the skipped goal satisfied?". Needs a `goal_likely_satisfied` heuristic per
   node + a prompt rule. Confirm the heuristic set before coding.
3. **Merge `graph-orchestrator` → `master`** once (1) is green. It's two logical
   units (judge redesign + replanner reliability) — two PRs, or one squash.
4. Lower-priority: harder privesc time-box, more targets (true Jenkins = Windows
   MS3), lab-hygiene automation folded into the run drivers.

---

## 10. Key design decisions & why (so you don't relitigate them)

- **Graph orchestrator replaced the old linear 5-stage pipeline** so the run can
  branch/backtrack/replan. The old `single_focus.py` linear agent is dead.
- **`judge()` (L2) was the central VulnBot-inspired change** — catch drift
  *between* nodes with a light `continue/adapt/escalate` call instead of only the
  heavyweight replanner firing when fully stuck.
- **The MSF version-gate was deliberately reversed to advisory.** An earlier
  "reject modules whose version doesn't match" gate pre-empted the failure signal
  the replanner needs; version mismatches are warnings, not blockers. Ground-truth
  validation is MSF's *catalog* (does the module exist?), not version heuristics.
- **Tiny-intent replanning.** The LLM emits `{action, target_hint, …}`, not a full
  AttackNode — asking it for ~12 nested fields under stress produced garbage. Code
  expands the intent.
- **gpt-4o for replan/judge** (see §6). Everything else defaults to mini for cost.

---

## 11. Directory map

```
core_agents/      THE orchestrator + graph engine (start here)
  orchestrator.py   run_graph, walker, judge(), _replan_from, dispatch, _find_session
  attack_graph.py   AttackGraph/Node/Edge/EdgeCheck dataclasses + JSON (de)serialize
  state.py          Findings TypedDicts (stage output contracts) + STAGES order
  prompts.py        orchestrator-level Planner/Critic prompts
  common.py         KALI_IP, creds, default MODEL_NAME, call_llm helper, colors, FORBIDDEN
stages/           the 5 L1 subagents (recon, initial_access, privesc, persistence, impact)
tools/            metasploit_tools.py (RPC session wrapper), rag.py (Chroma KB queries)
examples/         attack graphs — *_graph.py build_*_graph(); goal_only + flaw_* test the subagents
experiments/      live_test_*.py drivers (+ restart_msf.py lab helper, ad-hoc test_stage_* — stale)
tests/            offline unit tests + run_offline.py (your safety net)
database_utils/   build_database.py (RAG ingestion → ChromaDB)
reports/          the deep docs (see index below)
logs/             per-run logs (grep [Dispatch]/[direct]/[Replanner])
graphs/           checkpointed graph state (resume support)
legacy_agents/    single_focus.py — DEAD, the old linear agent (do not use)
databases/, my_knowledge_base/   the RAG vector store
```

**Stale/broken to ignore:** `legacy_agents/` (dead), `refined.py` (never existed —
CLAUDE.md lies), root `test_recon_only.py` (imports a `build_pipeline` that no
longer exists), `experiments/test_stage_*.py` (ad-hoc, not in the offline suite).

---

## 12. The deeper docs (read in this order)

1. `HANDOFF.md` ← you are here
2. `docs/DESIGN_PHILOSOPHY.md` — *why* it's built this way (the 3-layer model, "failure is signal," the logical-vs-design bug method); read this before making structural changes
3. `reports/refinement_history_v0_v19.md` — the whole evolution, problem→design per version
3. `reports/refinement_roadmap.md` — open work, prioritized
4. `reports/pipeline_end_to_end_journey.md` — a concrete replanner recovery walkthrough (disk-wipe fixture)
5. `reports/stage_refinement_cycle_log.md` — raw run-by-run results
6. Root plan files (`judge_redesign_plan.md`, `replanner_reliability_plan.md`,
   `credential_retry_plan.md`) — historical design notes, mostly now implemented

---

## 13. Glossary

- **direct path** — node executed over MSF/SSH with no LLM (has module/commands).
- **subagent path** — goal-only (or failed-direct) node handed to a `stages/` agent.
- **explore mode** — `run_graph(..., explore=True)`; enables subagent fallback + replanner.
- **goal-only node** — node with a goal but no module/commands → forces subagent.
- **replanner / L3** — `_replan_from`; grows/mutates the graph when stuck.
- **judge / L2** — `judge()`; between-node continue/adapt/escalate.
- **tiny intent** — the small JSON the replanner LLM emits; code expands to a node.
- **grounding** — verifying success against real tool output, not LLM prose.
- **`[PROVEN]`** — a vector with prior successful-attack evidence; preferred on retry (v17).
- **confounder** — a lab-state problem (wedged msfrpcd, IP drift) that mimics a bug.
```
