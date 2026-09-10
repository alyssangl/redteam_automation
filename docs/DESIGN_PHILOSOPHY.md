# Design Philosophy

The reasoning behind *why lgg_automation is built the way it is* — distilled from
the original author's design docs (`Lessons from VulnBot`, the refinement-workflow
notes, and the progression of design presentations). If `HANDOFF.md` tells you
*what* the system is and *how* to run it, this tells you *why*, so you extend it
in the same spirit instead of fighting its grain.

---

## 0. How the architecture got here (the evolution)

The current design is the endpoint of a deliberate progression — each step was a
reaction to a concrete failure of the previous one:

1. **Monolithic Main Agent** (Planner + Critic + RAG + success logging).
   → *Problem:* the main agent skipped steps and overstepped its boundaries.
2. **Decompose into Planner / Executor / Critic** — for preciseness and scope
   limitation. → *Problem:* gpt-4o was too expensive, RAG retrieval burned tokens,
   and the executor lacked knowledge of the commands it was using.
3. **Decompose further** — add a **Researcher** and a **Parameter Solver** so each
   role has a tight job. → *Realization:* *"I think I'm polishing a single
   kill-chain stage too much."* One stage was over-engineered while the pipeline
   as a whole had no good progress-tracking structure.
4. **Adopt a directed graph** as the progress-tracking data structure — nodes =
   actions, edges = decisions — so the run can branch, backtrack, and be audited,
   instead of a rigid linear plan.
5. **The 3-layer decision model** (from studying VulnBot) — keep the strong
   in-node tactical loop and the heavyweight replanner, and add the missing
   *middle* layer (`judge()`) that reviews between nodes.

The throughline: **decompose for scope, make progress a graph, and put judgment
at the right layer.** Every principle below is a corollary of that.

---

## 1. The three-layer decision model (the core idea)

Decision-making is split across three layers, and *which layer the LLM enters at*
is the single most important design choice.

| Layer | Where | What | Status |
|---|---|---|---|
| **L1 Tactical** | *inside* a node | stage subagents' ReAct loop — pick a command, observe, iterate | strength; keep |
| **L2 Strategic** | *between* nodes | `judge()` — after each retry-failure / node completion: `continue \| adapt \| escalate` | the central addition |
| **L3 Heavyweight** | graph mutation | `_replan_from()` — grow edges, add nodes | last resort; fires rarely once L2 catches drift |

> VulnBot only had L2. This project already had L1 and L3 — the insight was to
> add the missing middle. With L2 catching most drift early, L3 fires rarely and
> on smaller mismatches.

**The LLM enters at L2 (judge), never inside L1's deterministic routing.** That
placement is what preserves replayability, audit, and strict-mode (see §2).

---

## 2. Determinism where it counts; the LLM where it helps

Hand-authored **edges are testable claims**, not just ordering. An `EdgeCheck`
(`field, operator, expected`) evaluates deterministically at runtime with rich
predicates ("port 21 is ProFTPD 1.3.5 AND os contains Linux"). This is where the
project *outperforms* a pure-LLM planner — **do not lose it.**

- **Keep** `EdgeCheck.evaluate()` deterministic. Hand-authored edges keep rich
  predicates. Replayability / audit / strict-mode all depend on this.
- **Change** only the LLM-*grown* edges: those are lightweight
  `(source, target, rationale_string)`. The LLM never emits a full `EdgeCheck`,
  which kills six failure modes at once (wrong field name, operator typo,
  expected-shape mismatch, type drift, key drift, condition-vocab drift).
- **The LLM goes one level up.** Judgment lives in the small `judge()` *above* the
  procedural EdgeCheck routing, not inside it.

---

## 3. Lower the emission bar

**Never ask the LLM to emit a full structured object under stress.** A full
`AttackNode` is ~25 fields (module, options, payload, alts, agent_type, …). Asking
for that *after a failure* produces garbage.

Instead the LLM emits a **tiny intent** — `{action, target, hint}` — and **code
expands it into a node** (`_expand_intent_to_node`). Defaults like
`payload_options.LHOST` are just `graph.attacker_ip`; the code fills them.

Corollary — **audit which fields are load-bearing.** `goal`/`objective` overlap;
`technique_name` is derivable from `technique_id`. Reporting-only fields belong in
`metadata`, not in what the LLM has to reason about or emit.

---

## 4. Failure is signal — don't pre-empt it with gates

A pre-validation gate that rejects an idea *before running it* throws away the
most useful information: the actual failure.

- The old `MSF_MODULE_REQUIREMENTS` semantic **version-matching gate** rejected
  correct proposals (a 1.3.5 exploit on a 1.3.4 target) and was **deliberately
  demoted to advisory.** Wrong proposals should be *allowed to run and fail* —
  that failure is signal the replanner needs.
- **Keep structural validation** (required fields present, OS category sane,
  module path actually exists in the MSF catalog — ground truth). **Drop semantic
  matching**, or make it a warning.

This is a recurring stance: validate *post-hoc* against reality, not *a priori*
against a heuristic.

---

## 5. Feed the LLM prose, not just typed findings

Structured findings throw away exactly the detail an operator reads to diagnose a
failure. So:

- **Stop stripping `raw_nmap_output`.** Pass the last few `CommandRecord.output`
  (capped ~2 KB each) into judge/replanner context.
- The LLM should see **banners, stderr, exit codes** — the messy result string —
  not only the typed summary. (This is what a pure-LLM planner gets "for free"
  from its raw result string, and what over-structuring silently discards.)

## 6. Review every step, not only on failure

Run a lightweight LLM check (the `judge()`) **after every node**, not just when
fully stuck. By the time the rigid `alts → replan → backtrack` sequence gives up,
you've already missed three chances to self-correct on *fresh* context. Cheaper
calls, smaller stakes, earlier correction. Most `judge()` calls return `continue`;
only ~10% mutate the graph.

Corollary — **alts and replan are parallel options the judge picks between**, not
a fixed sequence. The judge can escalate after retry 1 if the failure pattern says
the remaining alternatives obviously won't help. No mandatory walk through
`max_retries`.

## 7. Grounding beats prose (trust the target, not the model)

Weaker/cheaper models hallucinate success. So every stage's critic does an
**independent ground-truth check**: run `id` *inside the session*, attach the raw
tool output as evidence, and return a **mandatory FAIL when unverified**. A stage
never gets to claim success on its own say-so. This principle is load-bearing —
the #1 recurring bug class was false success, and grounding is the antidote. (It
also has to be session-type-aware: `id` for a command_shell, `getuid` for
meterpreter — see the v16c privesc work.)

## 8. Tight scope, rich capability inside it

Each stage subagent must stay **precise to its own kill-chain scope** — it must
not bleed into other stages or take over planning/orchestration (that's a
different layer). **But within that scope its tools and prompts should be broad
and capable** — not narrowed to one rigid command pattern.

The failure mode to avoid is a pipeline that feels "too formatted" and can't
attack a real machine freely. Over-narrow tooling cripples a stage even when its
scope is right. Aim for **tight scope, rich capability** — and beware the opposite
trap the author flagged on themselves: *"polishing a single kill-chain stage too
much"* while the system-level structure lags.

---

## 9. The refinement methodology (how to work on this)

The dev loop that produced v0→v19:

```
run the current workflow
      │
      ▼
catch a bug ──► classify it
      │            ├─ LOGICAL bug: I didn't intend it; it happened because of bad code
      │            └─ DESIGN  bug: it worked out badly because my design is bad
      ▼
test on a single graph  ──►  test on ALL current test graphs
```

**The logical-vs-design distinction is the key mental tool.** A *logical* bug gets
a code patch (a missing timeout, a message-window slice, a stderr not captured). A
*design* bug means the shape is wrong and you rethink it (the version-gate
pre-empting failure; the replanner having no `judge()` layer; asking the LLM for
25 fields). Don't patch a design bug with more code — it'll resurface.

Supporting practices:

- **Test on flawed graphs.** `examples/flaw_*_graph.py` deliberately break one
  stage each, to test the pipeline's *adaptation*, not just its happy path.
- **Offline-first.** Turn every live-run discovery into a fast unit test
  (`tests/`); a 5-second check beats a 40-minute live run.
- **Commit per change.** Small, self-contained commits so any single change is
  revertible; keep the cycle log + roadmap current.
- **A commit/version per problem→fix**, with the problem written down — which is
  why `reports/refinement_history_v0_v19.md` reads as a list of
  problem→design→commit.

---

## 10. What we deliberately keep vs. change (vs. VulnBot)

| | Keep | Change |
|---|---|---|
| **Node** | rich per-node execution detail | don't make the LLM *emit* it — tiny intent, expand in code |
| **Edge** | deterministic hand-authored `EdgeCheck` (replayable, auditable) | LLM-grown edges are lightweight `(src, tgt, rationale)` |
| **In-node loop (L1)** | the ReAct tactical loop — a strength | — |
| **Between-node (L2)** | — | ADD `judge()`: the central change |
| **Graph mutation (L3)** | `_replan_from()` | fires less once L2 exists; lower its emission bar |
| **Validation** | structural + catalog (ground truth) | semantic version-match → advisory only |
| **Context to LLM** | typed findings | ALSO feed raw prose (nmap, stderr, exit codes) |

---

## Sources

Authored by the original developer (in `~/Downloads/nslab/`, not in the repo):
`Lessons from VulnBot.pdf` (the 3-layer model + the five takeaways + the unified
judge), the refinement-workflow notes (logical-vs-design bug loop), and the design
presentations (the monolith→decompose→graph→3-layer evolution). Distilled here so
the reasoning survives without the slides.
