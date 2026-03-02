"""
Orchestrator Pipeline — top-level LangGraph workflow.

Architecture:
    Planner ⟺ RAG tools → Recon → Initial Access → Persistence* → PrivEsc* → Impact* → Critic
                                                                                          ↓
                                                                              PASS → Success Logger → END
                                                                              FAIL → Planner (max 3 retries)

    (* = stub stages, not yet implemented)

Usage:
    python -m core_agents.orchestrator               # Interactive REPL
    python -m core_agents.orchestrator --graph        # Print graph topology

    from core_agents.orchestrator import run_pipeline
    result = run_pipeline(target_ip="192.168.34.7", objective="Get a shell on the target")
"""

import sys
import json
import time
from typing import Literal

from langchain_core.messages import HumanMessage, AIMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver

from core_agents.state import PipelineState, STAGES
from core_agents.common import (
    Colors, print_colored, call_llm, MAX_PIPELINE_RETRIES,
)
from core_agents.prompts import PLANNER_PROMPT, CRITIC_PROMPT

from stages.recon import run_recon
from stages.initial_access import run_exploitation

from tools.rag import query_knowledge_base, query_successful_attacks, log_successful_attack

# =============================================================================
# PLANNER TOOLS (RAG lookups available to the planner)
# =============================================================================

PLANNER_TOOLS = [query_successful_attacks, query_knowledge_base]

# =============================================================================
# NODE: PLANNER
# =============================================================================

def planner_node(state: PipelineState) -> dict:
    """LLM reads objective + past successes + critic feedback, produces attack plan."""
    objective = state.get("objective", "")
    target_ip = state.get("target_ip", "")
    critic_feedback = state.get("critic_feedback", "")
    loop_step = state.get("loop_step", 0)

    print_colored(f"\n[Pipeline] Planner node (attempt {loop_step + 1}/{MAX_PIPELINE_RETRIES})", Colors.HEADER)

    context = f"OBJECTIVE: {objective}\nTARGET IP: {target_ip}\n"
    if critic_feedback:
        context += f"\nCRITIC FEEDBACK FROM PREVIOUS ATTEMPT:\n{critic_feedback}\n"

    # Include prior stage findings summary on retry so planner knows what was tried
    if loop_step > 0:
        recon = state.get("recon_findings", {})
        exploit = state.get("exploitation_findings", {})
        if recon:
            context += f"\nPREVIOUS RECON SUMMARY: {recon.get('summary', 'N/A')}\n"
        if exploit:
            context += f"\nPREVIOUS EXPLOITATION SUMMARY: {exploit.get('summary', 'N/A')}\n"
            context += f"  Exploit used: {exploit.get('exploit_used', 'N/A')}\n"
            context += f"  Success: {exploit.get('success', False)}\n"

    response = call_llm(
        messages=[HumanMessage(content=context)],
        system_prompt=PLANNER_PROMPT,
        tools=PLANNER_TOOLS,
    )

    return {"messages": [response]}


def planner_tools_node(state: PipelineState) -> dict:
    """Execute RAG tool calls from the planner."""
    tool_node = ToolNode(PLANNER_TOOLS)
    return tool_node.invoke(state)


def route_after_planner(state: PipelineState) -> Literal["planner_tools", "recon_stage"]:
    """Route planner output: tool call -> planner_tools, text -> recon stage."""
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        return "planner_tools"
    # Extract plan text and store it
    return "recon_stage"

# =============================================================================
# NODE: PLAN EXTRACTOR (captures plan text before entering stages)
# =============================================================================

def plan_extractor_node(state: PipelineState) -> dict:
    """Extract the plan text from the planner's final response."""
    # Find the last AI message with text content (the plan)
    plan_text = ""
    for msg in reversed(state["messages"]):
        if isinstance(msg, AIMessage) and msg.content and not getattr(msg, "tool_calls", None):
            plan_text = msg.content
            break

    print_colored(f"[Pipeline] Plan captured ({len(plan_text)} chars)", Colors.OKGREEN)
    if plan_text:
        print_colored(f"[Pipeline] Plan preview:\n{plan_text[:500]}", Colors.OKBLUE)

    return {"plan": plan_text}

# =============================================================================
# STAGE NODES
# =============================================================================

def recon_stage_node(state: PipelineState) -> dict:
    """Run the recon subgraph and capture findings."""
    print_colored("\n[Pipeline] Running Recon stage...", Colors.HEADER)

    findings = run_recon(
        target_ip=state["target_ip"],
        goal=state["objective"],
    )

    return {
        "recon_findings": dict(findings),
        "current_stage": "recon",
        "messages": [AIMessage(content=f"[Recon Complete] {findings['summary']}")],
    }


def initial_access_stage_node(state: PipelineState) -> dict:
    """Run the exploitation subgraph using recon findings."""
    print_colored("\n[Pipeline] Running Initial Access stage...", Colors.HEADER)

    recon = state.get("recon_findings", {})
    target_info = recon.get("target_info", {"ip": state["target_ip"]})
    raw_nmap = recon.get("raw_nmap_output", "")

    findings = run_exploitation(
        target_info=target_info,
        objective=state["objective"],
        raw_recon=raw_nmap,
    )

    return {
        "exploitation_findings": dict(findings),
        "current_stage": "initial_access",
        "messages": [AIMessage(content=f"[Initial Access Complete] {findings['summary']}")],
    }


def persistence_stage_node(state: PipelineState) -> dict:
    """Stub — persistence stage not yet implemented."""
    print_colored("\n[Pipeline] Persistence stage (stub — not implemented)", Colors.WARNING)
    findings = {
        "success": False,
        "method": "",
        "details": "",
        "summary": "Persistence stage not yet implemented.",
    }
    return {
        "persistence_findings": findings,
        "current_stage": "persistence",
        "messages": [AIMessage(content="[Persistence] Skipped — not yet implemented.")],
    }


def privesc_stage_node(state: PipelineState) -> dict:
    """Stub — privilege escalation stage not yet implemented."""
    print_colored("\n[Pipeline] PrivEsc stage (stub — not implemented)", Colors.WARNING)
    findings = {
        "success": False,
        "technique": "",
        "previous_level": "",
        "new_level": "",
        "summary": "Privilege escalation stage not yet implemented.",
    }
    return {
        "privesc_findings": findings,
        "current_stage": "privesc",
        "messages": [AIMessage(content="[PrivEsc] Skipped — not yet implemented.")],
    }


def impact_stage_node(state: PipelineState) -> dict:
    """Stub — impact stage not yet implemented."""
    print_colored("\n[Pipeline] Impact stage (stub — not implemented)", Colors.WARNING)
    findings = {
        "success": False,
        "actions": [],
        "summary": "Impact stage not yet implemented.",
    }
    return {
        "impact_findings": findings,
        "current_stage": "impact",
        "messages": [AIMessage(content="[Impact] Skipped — not yet implemented.")],
    }

# =============================================================================
# NODE: CRITIC
# =============================================================================

def critic_node(state: PipelineState) -> dict:
    """Evaluate all stage findings against the objective."""
    objective = state.get("objective", "")
    plan = state.get("plan", "")
    loop_step = state.get("loop_step", 0)

    print_colored(f"\n[Pipeline] Critic evaluating results (attempt {loop_step + 1})...", Colors.HEADER)

    # Build evidence summary for the critic
    evidence = f"OBJECTIVE: {objective}\n\nPLAN:\n{plan}\n\n"

    recon = state.get("recon_findings", {})
    exploit = state.get("exploitation_findings", {})
    persist = state.get("persistence_findings", {})
    privesc = state.get("privesc_findings", {})
    impact = state.get("impact_findings", {})

    evidence += f"RECON FINDINGS:\n  Success: {recon.get('success', 'N/A')}\n  Summary: {recon.get('summary', 'N/A')}\n\n"
    evidence += (
        f"EXPLOITATION FINDINGS:\n"
        f"  Success: {exploit.get('success', 'N/A')}\n"
        f"  Session ID: {exploit.get('session_id', 'N/A')}\n"
        f"  Session Type: {exploit.get('session_type', 'N/A')}\n"
        f"  Exploit Used: {exploit.get('exploit_used', 'N/A')}\n"
        f"  Access Level: {exploit.get('access_level', 'N/A')}\n"
        f"  Summary: {exploit.get('summary', 'N/A')}\n\n"
    )
    evidence += f"PERSISTENCE FINDINGS:\n  Summary: {persist.get('summary', 'N/A')}\n\n"
    evidence += f"PRIVESC FINDINGS:\n  Summary: {privesc.get('summary', 'N/A')}\n\n"
    evidence += f"IMPACT FINDINGS:\n  Summary: {impact.get('summary', 'N/A')}\n\n"
    evidence += f"ATTEMPT: {loop_step + 1} of {MAX_PIPELINE_RETRIES}\n"

    response = call_llm(
        messages=[HumanMessage(content=evidence)],
        system_prompt=CRITIC_PROMPT,
    )

    verdict_text = response.content.strip()
    print_colored(f"[Critic] {verdict_text[:400]}", Colors.OKCYAN)

    # Parse verdict
    upper = verdict_text.upper()
    if "VERDICT: PASS" in upper or ("PASS" in upper and "FAIL" not in upper):
        verdict = "PASS"
    else:
        verdict = "FAIL"

    print_colored(
        f"[Critic] Verdict: {verdict}",
        Colors.OKGREEN if verdict == "PASS" else Colors.FAIL,
    )

    return {
        "critic_verdict": verdict,
        "critic_feedback": verdict_text if verdict == "FAIL" else "",
        "loop_step": loop_step + 1,
        "messages": [AIMessage(content=f"[Critic] {verdict}: {verdict_text[:200]}")],
    }

# =============================================================================
# NODE: SUCCESS LOGGER
# =============================================================================

def success_logger_node(state: PipelineState) -> dict:
    """Log the successful attack chain to the RAG knowledge base."""
    print_colored("\n[Pipeline] Logging successful attack...", Colors.OKGREEN)

    recon = state.get("recon_findings", {})
    exploit = state.get("exploitation_findings", {})
    objective = state.get("objective", "")
    target_ip = state.get("target_ip", "")

    log_entry = (
        f"SUCCESSFUL ATTACK LOG\n"
        f"Objective: {objective}\n"
        f"Target: {target_ip}\n"
        f"Recon: {recon.get('summary', 'N/A')}\n"
        f"Exploit: {exploit.get('exploit_used', 'N/A')}\n"
        f"Session: {exploit.get('session_type', 'N/A')} (ID: {exploit.get('session_id', 'N/A')})\n"
        f"Access Level: {exploit.get('access_level', 'N/A')}\n"
        f"Summary: {exploit.get('summary', 'N/A')}\n"
    )

    try:
        result = log_successful_attack(
            content=log_entry,
            metadata={"target": target_ip, "exploit": exploit.get("exploit_used", "")},
        )
        print_colored(f"[Success Logger] {result}", Colors.OKGREEN)
    except Exception as e:
        print_colored(f"[Success Logger] Failed to log: {e}", Colors.WARNING)

    return {
        "messages": [AIMessage(content=f"[Success Logger] Attack chain logged for future reference.")],
    }

# =============================================================================
# ROUTING
# =============================================================================

def route_after_critic(state: PipelineState) -> Literal["success_logger", "planner"]:
    """Route based on critic verdict: PASS -> success logger, FAIL -> planner retry."""
    time.sleep(2)  # Rate limiting

    verdict = state.get("critic_verdict", "FAIL")
    loop_step = state.get("loop_step", 0)

    if verdict == "PASS":
        return "success_logger"

    if loop_step >= MAX_PIPELINE_RETRIES:
        print_colored(
            f"[Pipeline] MAX RETRIES ({MAX_PIPELINE_RETRIES}) reached. Ending pipeline.",
            Colors.FAIL,
        )
        # Route to success_logger anyway to log partial results, then END
        return "success_logger"

    print_colored(
        f"[Pipeline] Critic says FAIL. Re-planning (attempt {loop_step + 1})...",
        Colors.WARNING,
    )
    return "planner"

# =============================================================================
# GRAPH CONSTRUCTION
# =============================================================================

def build_pipeline() -> StateGraph:
    """Construct the orchestrator pipeline graph."""
    workflow = StateGraph(PipelineState)

    # Add nodes
    workflow.add_node("planner", planner_node)
    workflow.add_node("planner_tools", planner_tools_node)
    workflow.add_node("plan_extractor", plan_extractor_node)
    workflow.add_node("recon_stage", recon_stage_node)
    workflow.add_node("initial_access_stage", initial_access_stage_node)
    workflow.add_node("persistence_stage", persistence_stage_node)
    workflow.add_node("privesc_stage", privesc_stage_node)
    workflow.add_node("impact_stage", impact_stage_node)
    workflow.add_node("critic", critic_node)
    workflow.add_node("success_logger", success_logger_node)

    # Entry point
    workflow.set_entry_point("planner")

    # Planner ReAct loop: planner <-> planner_tools, then into stages
    workflow.add_conditional_edges(
        "planner",
        route_after_planner,
        {"planner_tools": "planner_tools", "recon_stage": "plan_extractor"},
    )
    workflow.add_edge("planner_tools", "planner")

    # Plan extractor -> recon
    workflow.add_edge("plan_extractor", "recon_stage")

    # Linear stage pipeline
    workflow.add_edge("recon_stage", "initial_access_stage")
    workflow.add_edge("initial_access_stage", "persistence_stage")
    workflow.add_edge("persistence_stage", "privesc_stage")
    workflow.add_edge("privesc_stage", "impact_stage")
    workflow.add_edge("impact_stage", "critic")

    # Critic routing
    workflow.add_conditional_edges(
        "critic",
        route_after_critic,
        {"success_logger": "success_logger", "planner": "planner"},
    )

    # Success logger -> END
    workflow.add_edge("success_logger", END)

    return workflow

# =============================================================================
# PIPELINE RUNNER
# =============================================================================

def run_pipeline(target_ip: str, objective: str) -> dict:
    """Main entry point. Builds graph, runs to completion, returns final state.

    Args:
        target_ip: IP address of the target.
        objective: Attack objective string.

    Returns:
        Dict with all stage findings and pipeline metadata.
    """
    import uuid

    thread_id = f"pipeline_{uuid.uuid4().hex[:8]}"

    workflow = build_pipeline()
    checkpointer = MemorySaver()
    app = workflow.compile(checkpointer=checkpointer)

    config = {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": 200,
    }

    initial_state = {
        "messages": [HumanMessage(content=f"Attack objective: {objective}\nTarget: {target_ip}")],
        "objective": objective,
        "target_ip": target_ip,
        "plan": "",
        "current_stage": "",
        "recon_findings": {},
        "exploitation_findings": {},
        "persistence_findings": {},
        "privesc_findings": {},
        "impact_findings": {},
        "loop_step": 0,
        "critic_verdict": "",
        "critic_feedback": "",
    }

    print_colored(f"\n{'='*70}", Colors.HEADER)
    print_colored(f"[Pipeline] Starting orchestrator pipeline", Colors.HEADER)
    print_colored(f"  Target: {target_ip}", Colors.HEADER)
    print_colored(f"  Objective: {objective[:100]}", Colors.HEADER)
    print_colored(f"  Thread: {thread_id}", Colors.HEADER)
    print_colored(f"  Max retries: {MAX_PIPELINE_RETRIES}", Colors.HEADER)
    print_colored(f"{'='*70}\n", Colors.HEADER)

    # Stream to completion
    for event in app.stream(initial_state, config=config):
        for key, value in event.items():
            if not value or "messages" not in value:
                continue
            messages = value["messages"]
            if not isinstance(messages, list):
                messages = [messages]
            for msg in messages:
                if not hasattr(msg, "content") or not msg.content:
                    continue

                # Display pipeline-level messages
                content = msg.content
                if content.startswith("[Critic]"):
                    color = Colors.OKGREEN if "PASS" in content else Colors.FAIL
                    print_colored(f"\n{content[:500]}", color)
                elif content.startswith("[Success Logger]"):
                    print_colored(f"\n{content}", Colors.OKGREEN)
                elif any(content.startswith(f"[{tag}") for tag in
                         ["Recon Complete", "Initial Access Complete",
                          "Persistence", "PrivEsc", "Impact"]):
                    print_colored(f"\n{content}", Colors.OKCYAN)

                # Show tool calls
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    for t in msg.tool_calls:
                        print_colored(
                            f"   (Calling Tool: {t['name']} args: {str(t['args'])[:200]}...)",
                            Colors.OKCYAN,
                        )

    # Extract final state
    final_snapshot = app.get_state(config)
    final_state = final_snapshot.values

    # Print summary
    print_colored(f"\n{'='*70}", Colors.HEADER)
    print_colored("[Pipeline] COMPLETE", Colors.HEADER)
    print_colored(f"  Verdict: {final_state.get('critic_verdict', 'N/A')}", Colors.HEADER)
    print_colored(f"  Attempts: {final_state.get('loop_step', 0)}", Colors.HEADER)

    exploit = final_state.get("exploitation_findings", {})
    if exploit.get("success"):
        print_colored(f"  Session: {exploit.get('session_type', '?')} #{exploit.get('session_id', '?')}", Colors.OKGREEN)
        print_colored(f"  Exploit: {exploit.get('exploit_used', '?')}", Colors.OKGREEN)
    else:
        print_colored(f"  Exploitation: No session obtained", Colors.FAIL)

    print_colored(f"{'='*70}\n", Colors.HEADER)

    return {
        "objective": final_state.get("objective", ""),
        "target_ip": final_state.get("target_ip", ""),
        "plan": final_state.get("plan", ""),
        "critic_verdict": final_state.get("critic_verdict", ""),
        "attempts": final_state.get("loop_step", 0),
        "recon_findings": final_state.get("recon_findings", {}),
        "exploitation_findings": final_state.get("exploitation_findings", {}),
        "persistence_findings": final_state.get("persistence_findings", {}),
        "privesc_findings": final_state.get("privesc_findings", {}),
        "impact_findings": final_state.get("impact_findings", {}),
    }

# =============================================================================
# MAIN / REPL
# =============================================================================

def main():
    """Interactive standalone mode or graph visualization."""

    if "--graph" in sys.argv:
        workflow = build_pipeline()
        app = workflow.compile()
        try:
            print(app.get_graph().draw_ascii())
        except Exception:
            graph = app.get_graph()
            print("Nodes:", [n for n in graph.nodes])
            print("Edges:", [(e.source, e.target) for e in graph.edges])
        return

    print_colored("--- Orchestrator Pipeline ---", Colors.OKGREEN)
    print_colored("Stages: Planner -> Recon -> Initial Access -> Persistence* -> PrivEsc* -> Impact* -> Critic", Colors.OKCYAN)
    print_colored("(* = stub, not yet implemented)\n", Colors.OKCYAN)

    target_ip = input("[Target IP]: ").strip()
    if not target_ip:
        print_colored("No target IP provided. Exiting.", Colors.FAIL)
        return

    objective = input("[Objective]: ").strip()
    if not objective:
        objective = f"Gain initial access (shell) on {target_ip}"
        print_colored(f"Using default objective: {objective}", Colors.WARNING)

    result = run_pipeline(target_ip=target_ip, objective=objective)

    print("\n" + json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
