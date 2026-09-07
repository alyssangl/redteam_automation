# Related work — autonomous LLM pentest agents

_Positioning table for the paper. Columns are chosen to isolate **our two claimed
contributions**: (a) independent, deterministic success grounding, and (b) a
graph walker with strategic replanning + backtracking (kill-chain modification).
Every other system is weak in at least one of these two._

_†  = cell to verify against the source paper before it goes in the manuscript
(see "Cells to confirm" at the bottom). Do not cite an unmarked-as-confirmed cell yet._

## The table

| System | Autonomy | Plan structure | Strategic replan | Backtrack / kill-chain edit | Success verification (grounding) | Tool execution | Open src | Eval rigor |
|---|---|---|---|---|---|---|---|---|
| **Ours** (graph-orchestrator) | Full | Attack **graph** (DAG walker) | **L2 judge every node + L3 graph-mutating replanner** | **Yes** — revive/re-parent nodes, re-route around injected failure | **Independent + deterministic** — raw target bytes (`uid=0(root)`, proof-marker read-back), never the agent's self-report | MSF RPC + SSH | Yes | Ablation (grounding/replan/determinism), grounded metrics, confounder exclusion |
| **PentestGPT** (Deng+, USENIX Sec '24) | Semi / operator-in-loop † | Pentesting **Task Tree** (PTT) | Re-prioritizes subtasks; no graph mutation † | No † | LLM parses tool output — no independent check † | Operator executes (limited auto) † | Yes | HTB + custom benchmark; success = flags/subtasks † |
| **HackingBuddyGPT** (Happe, Kaplan & Cito, EMSE '25) | Full | **Linear** ReAct loop (no plan struct) | Retry via next prompt; no strategic layer | No | **In-loop + privesc-endpoint only** — agent regex-checks `id` output for `uid=0` (real bytes, not the LLM's word); published rates are graded by an *external benchmark harness* that inspects the VM, not a general in-agent oracle; no grounding for other stages (it has none) | SSH (Linux privesc only) | Yes | Own single-vuln Linux-privesc VM benchmark; success = harness detects root |
| **VulnBot** (2025) | Full | **Penetration Task Graph** (PTG) † | Planner + summarizer; limited replan † | No † | LLM summarization of results; **version/semantic gate** (see our design notes) — no independent grounding † | Shell † | Yes | Own benchmark / AutoPenBench-style † |
| **AutoAttacker** (Xu+) | Full (post-exploit) † | Planner→summarizer→navigator, ~linear † | No † | No † | Summarizer LLM interprets output — no independent check † | **Metasploit** † | Partial † | Own post-breach scenarios † |

## How to read it (the paper argument)

Two columns have a check in the **Ours** row and nowhere else:

1. **Success verification (grounding).** Every other system decides "did it work?"
   from the LLM's own reading of the output — a circular measurement. We ground on
   **independent raw target bytes** (`uid=0(root)` from `id`, a proof-marker read
   back off disk) that the agent cannot fabricate. This is exactly what our
   `v3_noground` ablation isolates: strip it and `false_success` spikes.
2. **Backtracking / kill-chain modification.** PentestGPT's tree and VulnBot's PTG
   are *plans*, but they execute forward — neither restructures the chain when an
   injected failure blocks a branch. Our L3 replanner mutates the graph (revives
   session-dead nodes, re-parents onto a re-exploit), which is what our `flaw_*`
   recovery scenarios measure and what `v1_noreplan` ablates away.

Everything else (autonomy, real MSF control, open source) is **table stakes** — we
match the field but don't claim novelty there. Keep the paper's contribution
narrow to the two columns above; that's the defensible story.

## HBG × our results — architectural, not head-to-head

**This comparison is qualitative/architectural. It is NOT a same-testbed benchmark**
and must not be written as one: HBG's numbers come from *their* scheme (single-vuln
Debian VMs, GPT-4-Turbo, 60-round cap, harness-graded root) and ours from *ours*
(MS3 `192.168.34.7`, gpt-4o/-mini, five stages, our deterministic oracle). Different
targets, models, and metrics — so "HBG 33–83%" never lines up next to our rate.
Reviewers expect architectural positioning for related work, not a re-run of every
baseline; that is exactly what this section is.

**What HBG actually does (confirmed from `papers/hackingBuddyGpt.pdf`).** HBG is
*not* a "trusts the LLM's word" strawman. Its agent regex-checks real `id` output for
`uid=0` (an in-loop check on captured bytes), and its reported success (GPT-4-Turbo
33–83%, ≈ human 75%) is graded by an external benchmark harness that detects root on
the VM it controls. The paper reports **no false-success / overclaim metric** (its
"hallucination" is invented *commands*, not hallucinated success). So the honest
difference is **breadth + separation**, never "they overclaim":

| Axis | HackingBuddyGPT | Ours |
|---|---|---|
| Where grounding lives | In the acting loop (agent regexes `id`) + an external harness for scoring | A **separate deterministic oracle** (`parse_eval`) over run artifacts + per-stage critics that **mandate FAIL if unverified** |
| Stage coverage | **Privesc endpoint only** (it has no other stages) | **All five stages** — session-opened, `uid=0(root)`, proof-marker read-back |
| Kill-chain edit / recovery | None (linear retry) | L3 replanner mutates the graph (revive / re-parent) |

**Our live evidence (clean 40-cell campaign — `reports/eval_per_scenario.md`).**

| Scenario | Variant | Grounded success | Recovery | False success |
|---|---|---|---|---|
| orphan_c (capability loss) | v0_full | 80% | **80%** | 0% |
| orphan_c | v_nograft | 0% | 0% | 0% |
| flaw_privesc (technique fail control) | v0_full | 88% | 0% | 0% |
| flaw_privesc | v_nograft | 80% | 0% | 0% |

Read honestly:
- **Recovery/kill-chain-edit is empirically supported now** (orphan_c 80% vs 0% when
  the graft is disabled). This is the differentiator no baseline above — HBG
  included — has.
- **The grounding column is supported by DESIGN, not yet by a clean counterfactual.**
  `false_success` is 0% everywhere only because every clean run had grounding ON. The
  ablation that would make it *spike* (`v3_noground`) has **not been cleanly run** —
  the only grounding-off data (`v6_naive`) was confounded by the `sessions -i` wedge
  and archived. To turn the grounding claim from architectural into empirical, run
  `v3_noground` cleanly and show `false_success` rising; that is the pending
  experiment, and it lives entirely in *our* scheme (apples-to-apples), independent of
  HBG. **HBG is the architectural comparator; `v3_noground` is the empirical evidence.**

## Cells to confirm (before manuscript)

The †-marked cells are from working memory of these systems, not re-read from the
papers. Highest-risk claims to verify:

- **PentestGPT autonomy** — it has both an interactive (operator-in-loop) and a
  more-automated mode; state which you're comparing against, and whether it truly
  lacks backtracking or just doesn't call it that.
- **VulnBot PTG vs. replan** — confirm the PTG is static (built once) vs.
  re-planned mid-run; our "no graph mutation" claim hinges on this.
- **HackingBuddyGPT grounding** — ✅ CONFIRMED from the paper (EMSE '25, arXiv
  2310.11409v7, `papers/hackingBuddyGpt.pdf`): the agent regex-matches `uid=0` in real
  `id` output (in-loop, not the LLM's word), and its published rates are graded by an
  external harness (Fig. 1, "ExecuteCommand until root or 60 rounds"). No overclaim
  metric is reported. Frame our advantage as **breadth (all stages) + separation
  (deterministic oracle / mandatory-FAIL critic)**, NOT "they have none" and NOT "they
  overclaim." See the "HBG × our results" section above.
- **AutoAttacker open-source status + exact verification** — least certain row.

Once these are confirmed I can also add **CAI** (Cybersecurity AI, 2025) and
**Nebula** as extra rows if the instructor wants breadth.

---

## Full landscape — every comparable system + paper link

_Verified links (searched Aug 2026), grouped by architecture generation. Use this as
the Related Work bibliography backbone._

### Single-agent / foundational
- **PentestGPT** — Deng et al., *PentestGPT: Evaluating and Harnessing LLMs for
  Automated Penetration Testing*, **USENIX Security 2024**.
  arXiv [2308.06782](https://arxiv.org/abs/2308.06782) · code [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT)
  — Pentesting Task Tree (PTT), reasoning/generation/parsing sessions, operator-in-loop.
- **HackingBuddyGPT** — Happe, Kaplan & Cito, *LLMs as Hackers: Autonomous Linux
  Privilege Escalation Attacks*, **EMSE 2025**.
  arXiv [2310.11409](https://arxiv.org/abs/2310.11409) · code [hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT)
  — minimal LLM+SSH loop, Linux privesc, has a root-check.
- **AutoAttacker** — Xu et al., *AutoAttacker: A Large Language Model Guided System
  to Implement Automatic Cyber-attacks*, 2024.
  arXiv [2403.01038](https://arxiv.org/abs/2403.01038)
  — post-breach / hands-on-keyboard, drives Metasploit.

### Structured control (state machine / two-stage)
- **PenHeal** — Huang & Zhu, *PenHeal: A Two-Stage LLM Framework for Automated
  Pentesting and Optimal Remediation*, 2024.
  arXiv [2407.17788](https://arxiv.org/abs/2407.17788)
  — pentest + auto-remediation, multi-path exploration.
- **AutoPT** — Wu et al., *AutoPT: How Far Are We from the End2End Automated Web
  Penetration Testing?*, 2024.
  arXiv [2411.01236](https://arxiv.org/abs/2411.01236)
  — **finite state machine** (Agent states vs Rule states) to stop infinite loops;
  web-pentest focus. Closest prior art to our "deterministic tried-tracking" (v4).

### Multi-agent / graph-structured (the direct competitors)
- **PentestAgent** — *PentestAgent: Incorporating LLM Agents to Automated Penetration
  Testing*, 2024.
  arXiv [2411.05185](https://arxiv.org/abs/2411.05185)
  — RAG-grounded, role-based (recon/triage/exploit) multi-agent.
- **VulnBot** — Kong et al., *VulnBot: Autonomous Penetration Testing for A
  Multi-Agent Collaborative Framework*, 2025.
  arXiv [2501.13411](https://arxiv.org/abs/2501.13411) · code [KHenryAegis/VulnBot](https://github.com/KHenryAegis/VulnBot)
  — Penetration Task Graph (PTG), recon/scan/exploit agents. (In our design notes.)
- **Incalmo** ⚠️ — *Incalmo: An Autonomous LLM-assisted System for Red Teaming
  Multi-Host Networks* (a.k.a. *On the Feasibility of Using LLMs to Execute
  Multistage Network Attacks*), **IEEE S&P 2026**.
  arXiv [2501.16466](https://arxiv.org/abs/2501.16466)
  — **has an attack-graph service + environment-state service**; multi-host (25–50
  hosts), MHBench (37/40 vs. 3/40 for baselines). **The system whose "graph" claim
  most overlaps ours — read this one carefully (see note below).**
- **xOffense** — *xOffense: An Autonomous Multi-Agent Framework for Penetration
  Testing with Domain-Adapted LLMs*, 2025.
  arXiv [2509.13021](https://arxiv.org/abs/2509.13021)
  — fine-tuned open model (Qwen3-32B), recon/scan/exploit agents.
- **CAI (Cybersecurity AI)** — Mayoral-Vilches et al., *CAI: An Open, Bug
  Bounty-Ready Cybersecurity AI*, 2025.
  arXiv [2504.06017](https://arxiv.org/abs/2504.06017)
  — general open framework, HITL-optional, strong CTF results.

### Newest (late-2025 → 2026) — these overlap our contributions, cite carefully
- **CHECKMATE** — *Automated Penetration Testing with LLM Agents and Classical
  Planning*, Dec 2025. arXiv [2512.11143](https://arxiv.org/abs/2512.11143)
  — classical planner as an **external deterministic "brain"** (Planner-Executor-
  Perceptor); beats Claude Code by 20%. **Overlaps our determinism claim (v4).**
- **Red-MIRROR** — *Agentic LLM Autonomous Pentesting with Reflective Verification
  and Knowledge-augmented Interaction*, Mar 2026. arXiv [2603.27127](https://arxiv.org/abs/2603.27127)
  — **"reflective verification" + adaptive validation**; SOTA on XBOW (86% vs
  PentestAgent 50 / AutoPT 46 / VulnBot 6). **Overlaps our grounding claim (v3) —
  but reflection is LLM-on-LLM self-check, NOT independent target-state grounding.**
- **ZERO-APT** — *A Closed-Loop Adversarial Framework for LLM-Driven Pentesting
  under Intelligent Defense*, Jun 2026. arXiv [2606.05567](https://arxiv.org/abs/2606.05567)
  — **attacker–defender–judge** loop, separation of planning/execution, live LLM
  defender on Sysmon telemetry. **Overlaps our judge() (L2) — on an adversarial-
  defense axis, not fault-injection recovery.**
- **APT-Agent** — *Automated Penetration Testing using LLMs*, May 2026.
  arXiv [2605.24949](https://arxiv.org/abs/2605.24949)
- **Automation-Exploit** — *Multi-Agent LLM Framework for Adaptive Offensive
  Security with Digital-Twin Risk-Mitigated Exploitation*, Apr 2026.
  arXiv [2604.22427](https://arxiv.org/abs/2604.22427)
- **RapidPen** — *Fully Automated IP-to-Shell Pentesting*, Feb 2025.
  arXiv [2502.16730](https://arxiv.org/abs/2502.16730) — ReAct + RAG, ~60% on one HTB box.
- **ARACNE** — *An LLM-Based Autonomous Shell Pentesting Agent*, Feb 2025.
  arXiv [2502.18528](https://arxiv.org/abs/2502.18528) — SSH shell agent, dynamic plan update.

### Evaluation / reliability studies (cite for your metrics + threats-to-validity)
- *Hackers or Hallucinators? A Comprehensive Analysis of LLM-Based Automated
  Pentesting*, Apr 2026. arXiv [2604.05719](https://arxiv.org/abs/2604.05719)
- *How Reliable Are AI Attackers Against a Fixed Target? A 400-Run Empirical Study
  of LLM Pentesting Consistency*, May 2026. arXiv [2605.30096](https://arxiv.org/abs/2605.30096)
  — **directly supports your recon-flake / reliability framing.**
- *Benchmarking Practices in LLM-driven Offensive Security: Testbeds, Metrics,
  Experiment Design*, 2025. arXiv [2504.10112](https://arxiv.org/abs/2504.10112)
  — **cite this to justify your grounded-metric + confounder-exclusion protocol.**

### Survey (Related-Work backbone)
- *A Survey of LLM-Driven Penetration Testing: Taxonomy, Co-Evolution, and Open
  Challenges*, 2026. arXiv [2607.02605](https://arxiv.org/abs/2607.02605)
  — use its taxonomy to structure your Related Work section.

## ⚠️ The three 2026 papers that threaten each contribution (read these first)

| Your claim | Ablation | 2026 paper that overlaps | Why you still differ |
|---|---|---|---|
| Independent grounding | v3_noground | **Red-MIRROR** (reflective verification) | Their check is LLM reflecting on LLM output — still self-referential. You read **raw target bytes** the agent can't fabricate. |
| Strategic judge/replan | v1_noreplan | **ZERO-APT** (attacker-defender-judge) | Their loop adapts to a **live defender**; yours restructures the chain around an **injected fault** (recovery, not evasion). |
| Determinism | v4_nodeterm | **CHECKMATE** (classical planning brain) | Their planner is a full external PDDL-style solver; yours is lightweight deterministic tried-tracking + hand-authored EdgeChecks inside an LLM-grown graph. |

If a reviewer says "this has been done in 2026," these three are what they'll point
to. The honest answer is that each overlaps **one** column — none combines all three,
and none does independent target-state grounding. That intersection is your niche.

## ⚠️ Note on Incalmo (the overlap risk)

Incalmo also uses an "attack graph," so a reviewer WILL ask how you differ. The
distinction is real and worth stating explicitly:

- **Incalmo's graph is a *forward planning / asset-register abstraction*** — it
  structures action selection so an LLM can move laterally across **many hosts**.
  It is built to *reach* assets, not to *repair a broken chain*.
- **Our graph is a *backtracking recovery structure on a single deep kill-chain*** —
  the L3 replanner **mutates** it (revives session-dead nodes, re-parents onto a
  re-exploit) when an injected fault blocks a branch. That's a different axis:
  fault-injection recovery, not multi-host breadth.
- **Neither Incalmo nor any system above does independent deterministic grounding** —
  they all trust the LLM/summarizer's reading of success. That column stays uniquely
  ours regardless of the graph overlap.

Positioning line for the paper: *"Unlike multi-host planners (Incalmo) or task-graph
decomposers (VulnBot), we target single-target kill-chain **recovery** under injected
failure, and are the only system to verify success against independent target state
rather than the agent's own report."*
