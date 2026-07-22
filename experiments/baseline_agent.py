"""
baseline_agent.py — the naive single-loop baseline (ablation V6).

The external comparison for the paper: ONE LLM ReAct loop over the SAME tools the
orchestrator's subagents use (RAG, MSF console, session commands, Kali terminal),
with NO attack graph, NO judge (L2), and NO replanner (L3). It attacks the same
objective as V0 (pulled from the scenario's graph builder) so the rows are
comparable.

It writes the SAME artifacts as an orchestrator run so parse_eval grades it
uniformly:
  - a checkpoint JSON with a single OBJECTIVE node whose status is the agent's
    OWN success claim and whose findings hold whatever ground-truth evidence the
    loop actually captured (session opened / uid=0 / proof read-back). parse_eval
    then re-derives grounded/false success independently — a naive agent that
    over-claims without evidence shows up as false_success, which is the point.
  - a timestamped log ending in the "[Orchestrator] EXECUTION COMPLETE" +
    "Success rate: N%" markers parse_eval keys off.

Not part of the offline suite (needs the lab + an API key); driven by run_matrix
as the v6_naive variant.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from langchain_core.messages import HumanMessage, ToolMessage

from core_agents.common import call_llm, print_colored, Colors
from core_agents.attack_graph import AttackGraph, AttackNode, NodeStatus
from tools.rag import query_knowledge_base, query_successful_attacks
from tools.metasploit_tools import tool_session_command
# tool_metasploit_rpc / tool_linux_terminal are defined in the initial_access
# stage (persistent MSF console + SSH); reuse them so the baseline drives the
# exact same lab surface as the orchestrator.
from stages.initial_access import tool_metasploit_rpc, tool_linux_terminal

BASELINE_MODEL = os.getenv("LGG_BASELINE_MODEL", "gpt-4o")
MAX_STEPS = int(os.getenv("LGG_BASELINE_MAX_STEPS", "24"))

TOOLS = [
    query_successful_attacks, query_knowledge_base,
    tool_metasploit_rpc, tool_session_command, tool_linux_terminal,
]
_TOOLS_BY_NAME = {t.name: t for t in TOOLS}

SYSTEM_PROMPT = """You are an autonomous red-team operator on an authorized lab
engagement. You have a Kali attacker box with a persistent Metasploit console and
SSH terminal, plus a knowledge base of exploitation techniques.

Work the objective end to end on your own: research, exploit, escalate, persist,
and prove impact as the objective requires. Use ONE tool at a time and READ each
result before the next step. Non-interactive commands only (no ftp/ssh/vi/nano).

When you believe the objective is fully achieved, STOP calling tools and reply
with a final line beginning `RESULT: SUCCESS` or `RESULT: FAIL`, followed by a
short evidence summary quoting the concrete proof (session id, `id`/`uid=0`
output, the proof-file contents you read back)."""


def _objective_from_scenario(scenario: str, target: str, attacker: str) -> tuple[str, str, str]:
    """Return (objective_text, objective_node_id, objective_agent_type) by
    building the scenario graph and taking its deepest intended stage — so the
    baseline attacks the exact same goal V0 does."""
    from ui.registry import resolve_builder
    builder = resolve_builder(scenario)
    graph = builder(target_ip=target, attacker_ip=attacker)
    priority = ["impact", "persistence", "privesc", "exploit",
                "initial_access", "recon", "discovery"]
    by_type = {}
    for n in graph.nodes.values():
        by_type[(n.agent_type or "").lower()] = n
    obj_node = None
    for atype in priority:
        if atype in by_type:
            obj_node = by_type[atype]
            break
    obj_node = obj_node or next(iter(graph.nodes.values()), None)
    return (graph.objective, obj_node.id if obj_node else "objective",
            (obj_node.agent_type if obj_node else "impact"))


def _make_logger(log_path: str) -> logging.Logger:
    """A logger matching the orchestrator's file format (HH:MM:SS timestamps)
    so parse_eval's markers + wall-clock parsing work unchanged."""
    logger = logging.getLogger(f"baseline.{log_path}")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                      datefmt="%H:%M:%S"))
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(ch)
    return logger


def _invoke_tool(tool_call: dict) -> str:
    name = tool_call.get("name", "")
    args = tool_call.get("args", {}) or {}
    tool = _TOOLS_BY_NAME.get(name)
    if tool is None:
        return f"ERROR: unknown tool '{name}'"
    try:
        return str(tool.invoke(args))
    except Exception as e:  # a tool blowing up must not kill the loop
        return f"ERROR invoking {name}: {e}"


def _scrape_evidence(transcript: str) -> dict:
    """Independent ground-truth scrape from the loop transcript — the evidence
    parse_eval will grade grounding against."""
    findings: dict = {"success": None, "summary": ""}
    m = re.search(r"[Ss]ession (\d+) opened|Meterpreter session (\d+)"
                  r"|Command shell session (\d+)", transcript)
    if m:
        findings["session_id"] = next(g for g in m.groups() if g)
    if re.search(r"uid=0\(root\)|Server username: root", transcript):
        findings["new_level"] = "root"
    # a read-back proof marker (the impact stage convention)
    if re.search(r"pwned|COMPROMISED|red[_ ]?team", transcript, re.I):
        findings["output"] = "proof marker observed in read-back"
    return findings


def run_baseline(scenario: str, target: str, attacker: str,
                 checkpoint_path: str, log_path: str) -> AttackGraph:
    log = _make_logger(log_path)
    objective, obj_id, obj_type = _objective_from_scenario(scenario, target, attacker)

    log.info("=" * 70)
    log.info("[Baseline] Naive single-loop agent (ablation V6 — no graph/judge/replanner)")
    log.info(f"  Scenario: {scenario}  Target: {target}  Model: {BASELINE_MODEL}")
    log.info(f"  Objective: {objective}")
    log.info("=" * 70)

    messages = [HumanMessage(content=(
        f"TARGET: {target}\nATTACKER (Kali): {attacker}\n\nOBJECTIVE:\n{objective}"
    ))]

    claimed_success = False
    final_text = ""
    for step in range(MAX_STEPS):
        resp = call_llm(messages, system_prompt=SYSTEM_PROMPT, tools=TOOLS,
                        model_name=BASELINE_MODEL)
        messages.append(resp)
        tool_calls = getattr(resp, "tool_calls", None)
        if not tool_calls:
            final_text = (resp.content or "").strip()
            log.info(f"[Baseline] Final answer at step {step}: {final_text[:300]}")
            claimed_success = bool(re.search(r"RESULT:\s*SUCCESS", final_text, re.I))
            break
        for tc in tool_calls:
            log.info(f"[Baseline] step {step} tool={tc.get('name')} args={tc.get('args')}")
            out = _invoke_tool(tc)
            log.info(f"[Baseline] -> {str(out)[:200]}")
            messages.append(ToolMessage(content=str(out),
                                        tool_call_id=tc.get("id", f"call_{step}")))
    else:
        log.info(f"[Baseline] Step budget ({MAX_STEPS}) exhausted without a final answer")

    # Independent evidence scrape from the whole transcript.
    transcript = "\n".join(str(getattr(m, "content", "")) for m in messages)
    findings = _scrape_evidence(transcript)
    findings["success"] = claimed_success
    findings["summary"] = final_text[:400]

    # Synthesize a one-node checkpoint parse_eval can grade uniformly.
    graph = AttackGraph.create(objective=objective, target_ip=target,
                               attacker_ip=attacker, name=f"baseline_{scenario}")
    node = AttackNode(id=obj_id, label=f"Baseline objective ({scenario})",
                      agent_type=obj_type, goal=objective, objective=objective,
                      target_ip=target)
    node.status = (NodeStatus.SUCCESS.value if claimed_success
                   else NodeStatus.FAILED.value)
    node.findings = findings
    node.summary = final_text[:200] or ("claimed success" if claimed_success else "no success")
    graph.add_node(node)
    graph.status = "completed"
    graph.completed_at = datetime.now(timezone.utc).isoformat()
    graph.save(checkpoint_path)

    # Emit the summary markers parse_eval keys off (mirror _print_summary).
    rate = 100 if claimed_success else 0
    log.info("\n" + "=" * 70)
    log.info("[Orchestrator] EXECUTION COMPLETE")
    log.info(f"  Status: {graph.status}")
    log.info(f"  Success rate: {rate}%")
    icon = "✓" if claimed_success else "✗"
    log.info(f"  {icon} {obj_id}: {node.summary}")
    log.info("=" * 70)
    return graph


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Naive single-loop baseline agent.")
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--target", default="192.168.34.7")
    ap.add_argument("--attacker", default=os.getenv("LHOST", "192.168.34.6"))
    ap.add_argument("--checkpoint", default=None)
    ap.add_argument("--log", default=None)
    args = ap.parse_args()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    cp = args.checkpoint or f"logs/eval/baseline_{args.scenario}__v6_naive__manual_{ts}.json"
    lg = args.log or f"logs/eval/baseline_{args.scenario}__v6_naive__manual_{ts}.log"
    Path(cp).parent.mkdir(parents=True, exist_ok=True)
    run_baseline(args.scenario, args.target, args.attacker, cp, lg)
