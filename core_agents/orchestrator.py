"""
Graph-Driven Orchestrator — walks an AttackGraph, dispatching subagents per node.

Architecture:
    Load/receive AttackGraph
        │
        ▼
    ┌─ LOOP ─────────────────────────────────────────────┐
    │  ready = graph.ready_nodes()                       │
    │  if none → done                                    │
    │  for each ready node:                              │
    │    context = graph.gather_preceding_findings(node)  │
    │    dispatch to subagent (based on node.agent_type)  │
    │    write findings + commands back to node           │
    │    update graph status                             │
    │    graph.save() (checkpoint)                       │
    └────────────────────────────────────────────────────┘

Usage:
    from core_agents.orchestrator import run_graph
    from core_agents.attack_graph import AttackGraph

    graph = AttackGraph.load("examples/disk_wipe_graph.json")
    result = run_graph(graph)

    # Or interactively:
    python -m core_agents.orchestrator examples/disk_wipe_graph.json
"""

import sys
import json
import time
from pathlib import Path
from typing import Optional

from core_agents.attack_graph import AttackGraph, AttackNode, NodeStatus
from core_agents.common import Colors, print_colored, MAX_PIPELINE_RETRIES

from stages.recon import run_recon
from stages.initial_access import run_exploitation
from stages.persistence import run_persistence
from stages.privesc import run_privesc
from stages.impact import run_impact


# =============================================================================
# SUBAGENT DISPATCH — routes a node to the right stage runner
# =============================================================================

def dispatch_node(node: AttackNode, graph: AttackGraph) -> dict:
    """
    Execute a single node by dispatching to the appropriate subagent.

    Reads the node's self-contained config (module, options, objective, etc.)
    and upstream findings from the graph, then calls the matching stage runner.

    Returns the findings dict from the subagent.
    """
    agent_type = node.agent_type
    preceding = graph.gather_preceding_findings(node.id)

    print_colored(
        f"\n[Orchestrator] Dispatching node '{node.id}' ({node.label}) → agent: {agent_type}",
        Colors.HEADER,
    )
    if preceding:
        print_colored(
            f"  Preceding findings from: {list(preceding.keys())}",
            Colors.OKCYAN,
        )

    if agent_type == "recon":
        return _dispatch_recon(node, graph, preceding)
    elif agent_type == "exploit":
        return _dispatch_exploit(node, graph, preceding)
    elif agent_type == "persistence":
        return _dispatch_persistence(node, graph, preceding)
    elif agent_type == "privesc":
        return _dispatch_privesc(node, graph, preceding)
    elif agent_type == "impact":
        return _dispatch_impact(node, graph, preceding)
    elif agent_type == "discovery":
        return _dispatch_discovery(node, graph, preceding)
    else:
        print_colored(
            f"  [WARNING] Unknown agent_type '{agent_type}' — skipping node.",
            Colors.WARNING,
        )
        return {"success": False, "summary": f"Unknown agent_type: {agent_type}"}


# =============================================================================
# DISPATCH IMPLEMENTATIONS — one per agent type
# =============================================================================

def _dispatch_recon(node: AttackNode, graph: AttackGraph, preceding: dict) -> dict:
    """Dispatch to the recon stage runner."""
    findings = run_recon(
        target_ip=node.target_ip or graph.target_ip,
        goal=node.objective or graph.objective,
    )
    return dict(findings)


def _dispatch_exploit(node: AttackNode, graph: AttackGraph, preceding: dict) -> dict:
    """Dispatch to the exploitation stage runner."""
    # Build target_info from preceding recon findings if available
    target_info = {"ip": node.target_ip or graph.target_ip}
    raw_recon = ""

    for pred_id, pred_findings in preceding.items():
        # Look for recon-like findings
        if "ports" in pred_findings or "target_info" in pred_findings:
            target_info = pred_findings.get("target_info", target_info)
            raw_recon = pred_findings.get("raw_nmap_output", "")
            break

    # Pass the node's module/options as hint in the objective
    objective = node.objective or graph.objective
    if node.module:
        objective += (
            f"\n\nSUGGESTED MODULE: {node.module}"
            f"\nPayload: {node.payload}"
            f"\nOptions: {json.dumps(node.module_options)}"
        )
        if node.payload_options:
            objective += f"\nPayload options: {json.dumps(node.payload_options)}"

    findings = run_exploitation(
        target_info=target_info,
        objective=objective,
        raw_recon=raw_recon,
    )
    return dict(findings)


def _dispatch_persistence(node: AttackNode, graph: AttackGraph, preceding: dict) -> dict:
    """Dispatch to the persistence stage runner."""
    # Find session info from preceding exploit findings
    session_id = ""
    session_type = ""
    access_level = "unknown"

    for pred_id, pred_findings in preceding.items():
        if "session_id" in pred_findings and pred_findings.get("success"):
            session_id = str(pred_findings["session_id"])
            session_type = pred_findings.get("session_type", "shell")
            access_level = pred_findings.get("access_level", "unknown")
            break

    if not session_id:
        return {
            "success": False,
            "method": "",
            "details": "No active session from preceding nodes.",
            "summary": "Persistence skipped — no session available.",
        }

    # Pass module hint in objective
    objective = node.objective or graph.objective
    if node.module:
        objective += (
            f"\n\nSUGGESTED MODULE: {node.module}"
            f"\nPayload: {node.payload}"
            f"\nOptions: {json.dumps(node.module_options)}"
        )

    findings = run_persistence(
        target_ip=node.target_ip or graph.target_ip,
        session_id=session_id,
        session_type=session_type,
        access_level=access_level,
        objective=objective,
    )
    return dict(findings)


def _dispatch_privesc(node: AttackNode, graph: AttackGraph, preceding: dict) -> dict:
    """Dispatch to the privilege escalation stage runner."""
    session_id = ""
    session_type = ""
    access_level = "unknown"
    os_info = ""

    for pred_id, pred_findings in preceding.items():
        if "session_id" in pred_findings and pred_findings.get("success"):
            session_id = str(pred_findings["session_id"])
            session_type = pred_findings.get("session_type", "shell")
            access_level = pred_findings.get("access_level", "unknown")
        if "os_detected" in pred_findings:
            os_info = pred_findings["os_detected"]

    if not session_id:
        return {
            "success": False,
            "technique": "",
            "previous_level": "",
            "new_level": "",
            "summary": "PrivEsc skipped — no session available.",
        }

    findings = run_privesc(
        target_ip=node.target_ip or graph.target_ip,
        session_id=session_id,
        session_type=session_type,
        access_level=access_level,
        os_info=os_info,
        objective=node.objective or graph.objective,
    )
    return dict(findings)


def _dispatch_impact(node: AttackNode, graph: AttackGraph, preceding: dict) -> dict:
    """Dispatch to the impact stage runner."""
    session_id = ""
    session_type = ""
    access_level = "unknown"

    for pred_id, pred_findings in preceding.items():
        if "session_id" in pred_findings and pred_findings.get("success"):
            session_id = str(pred_findings["session_id"])
            session_type = pred_findings.get("session_type", "shell")
            access_level = pred_findings.get("access_level", "unknown")
        # PrivEsc may have escalated the level
        if "new_level" in pred_findings and pred_findings.get("success"):
            access_level = pred_findings["new_level"]

    if not session_id:
        return {
            "success": False,
            "actions": [],
            "summary": "Impact skipped — no session available.",
        }

    # Build prior findings summary from all predecessors
    prior_lines = []
    for pred_id, pred_findings in preceding.items():
        prior_lines.append(f"{pred_id}: {pred_findings.get('summary', 'N/A')}")
    prior_summary = "\n".join(prior_lines)

    # Include pre-planned commands in the objective
    objective = node.objective or graph.objective
    if node.commands_to_run:
        objective += f"\n\nPRE-PLANNED COMMANDS:\n" + "\n".join(
            f"  {i+1}. {cmd}" for i, cmd in enumerate(node.commands_to_run)
        )

    findings = run_impact(
        target_ip=node.target_ip or graph.target_ip,
        objective=objective,
        session_id=session_id,
        session_type=session_type,
        access_level=access_level,
        prior_findings_summary=prior_summary,
    )
    return dict(findings)


def _dispatch_discovery(node: AttackNode, graph: AttackGraph, preceding: dict) -> dict:
    """
    Dispatch discovery tasks.

    Discovery reuses the impact runner with a non-destructive objective
    (enumerate disks, list users, etc.) since both need an active session
    and run commands on the target.
    """
    session_id = ""
    session_type = ""
    access_level = "unknown"

    for pred_id, pred_findings in preceding.items():
        if "session_id" in pred_findings and pred_findings.get("success"):
            session_id = str(pred_findings["session_id"])
            session_type = pred_findings.get("session_type", "shell")
            access_level = pred_findings.get("access_level", "unknown")
        if "new_level" in pred_findings and pred_findings.get("success"):
            access_level = pred_findings["new_level"]

    if not session_id:
        return {
            "success": False,
            "actions": [],
            "summary": "Discovery skipped — no session available.",
        }

    prior_lines = []
    for pred_id, pred_findings in preceding.items():
        prior_lines.append(f"{pred_id}: {pred_findings.get('summary', 'N/A')}")

    objective = node.objective or "Enumerate target system"
    if node.commands_to_run:
        objective += f"\n\nPRE-PLANNED COMMANDS:\n" + "\n".join(
            f"  {i+1}. {cmd}" for i, cmd in enumerate(node.commands_to_run)
        )

    findings = run_impact(
        target_ip=node.target_ip or graph.target_ip,
        objective=objective,
        session_id=session_id,
        session_type=session_type,
        access_level=access_level,
        prior_findings_summary="\n".join(prior_lines),
    )
    return dict(findings)


# =============================================================================
# GRAPH WALKER — the main orchestration loop
# =============================================================================

def run_graph(
    graph: AttackGraph,
    checkpoint_path: Optional[str] = None,
) -> AttackGraph:
    """
    Walk an AttackGraph to completion.

    Each iteration:
      1. Find all ready nodes (pending + all incoming edges satisfied)
      2. Execute each ready node via dispatch_node()
      3. Write findings back to the node
      4. Mark node success/failed
      5. Update global graph state (sessions, credentials)
      6. Checkpoint (save to disk)
      7. Repeat until no ready nodes remain

    Args:
        graph: The AttackGraph to execute.
        checkpoint_path: If set, save graph state after each node completes.

    Returns:
        The same AttackGraph, now populated with findings and statuses.
    """
    if not checkpoint_path:
        checkpoint_path = f"graphs/{graph.name}_state.json"

    graph.status = "running"
    graph.started_at = graph.started_at or _now()

    print_colored(f"\n{'='*70}", Colors.HEADER)
    print_colored(f"[Orchestrator] Starting graph execution", Colors.HEADER)
    print_colored(f"  Graph: {graph.name} ({graph.id})", Colors.HEADER)
    print_colored(f"  Objective: {graph.objective}", Colors.HEADER)
    print_colored(f"  Target: {graph.target_ip}", Colors.HEADER)
    print_colored(f"  Nodes: {len(graph.nodes)}", Colors.HEADER)
    print_colored(f"{'='*70}\n", Colors.HEADER)

    iteration = 0
    max_iterations = len(graph.nodes) * (MAX_PIPELINE_RETRIES + 1)  # Safety cap

    while iteration < max_iterations:
        iteration += 1

        ready = graph.ready_nodes()
        if not ready:
            if graph.is_complete():
                print_colored("\n[Orchestrator] All nodes complete.", Colors.OKGREEN)
            else:
                # Some nodes are blocked — nothing more we can do
                _mark_blocked_nodes(graph)
                print_colored(
                    "\n[Orchestrator] No ready nodes and graph incomplete — "
                    "remaining nodes are blocked.",
                    Colors.WARNING,
                )
            break

        print_colored(
            f"\n[Orchestrator] Iteration {iteration} — ready nodes: {ready}",
            Colors.HEADER,
        )

        for node_id in ready:
            node = graph.get_node(node_id)
            node.mark_running()

            try:
                findings = dispatch_node(node, graph)

                success = findings.get("success", False)
                summary = findings.get("summary", "")

                if success:
                    node.mark_success(findings, summary)
                    print_colored(
                        f"  [OK] {node_id}: {summary}",
                        Colors.OKGREEN,
                    )
                    # Track sessions globally
                    if "session_id" in findings and findings.get("session_id"):
                        graph.active_sessions.append({
                            "session_id": str(findings["session_id"]),
                            "type": findings.get("session_type", "unknown"),
                            "target": node.target_ip or graph.target_ip,
                            "source_node": node_id,
                        })
                else:
                    reason = summary or "No success flag in findings"
                    node.mark_failed(reason)
                    if node.can_retry:
                        print_colored(
                            f"  [RETRY] {node_id}: {reason} "
                            f"(attempt {node.retries}/{node.max_retries})",
                            Colors.WARNING,
                        )
                    else:
                        print_colored(
                            f"  [FAILED] {node_id}: {reason}",
                            Colors.FAIL,
                        )

            except Exception as e:
                node.mark_failed(str(e))
                print_colored(
                    f"  [ERROR] {node_id}: {e}",
                    Colors.FAIL,
                )

            # Checkpoint after each node
            _checkpoint(graph, checkpoint_path)

            # Brief pause between nodes for rate limiting
            time.sleep(1)

    # Final status
    graph.status = "completed"
    graph.completed_at = _now()
    _checkpoint(graph, checkpoint_path)

    # Print summary
    _print_summary(graph)

    return graph


def _mark_blocked_nodes(graph: AttackGraph):
    """Mark any remaining PENDING nodes as BLOCKED."""
    for node in graph.nodes.values():
        if node.status == NodeStatus.PENDING.value:
            # Check if any predecessor failed
            preds = graph.predecessors(node.id)
            failed_preds = [
                pid for pid in preds
                if graph.nodes[pid].status == NodeStatus.FAILED.value
            ]
            if failed_preds:
                node.mark_blocked(
                    f"Predecessor(s) failed: {', '.join(failed_preds)}"
                )


def _checkpoint(graph: AttackGraph, path: str):
    """Save graph state to disk."""
    try:
        graph.save(path)
    except Exception as e:
        print_colored(f"  [WARNING] Checkpoint save failed: {e}", Colors.WARNING)


def _print_summary(graph: AttackGraph):
    """Print final execution summary."""
    print_colored(f"\n{'='*70}", Colors.HEADER)
    print_colored("[Orchestrator] EXECUTION COMPLETE", Colors.HEADER)
    print_colored(f"  Status: {graph.status}", Colors.HEADER)
    print_colored(f"  Success rate: {graph.success_rate():.0%}", Colors.HEADER)
    print()

    for node in graph.nodes.values():
        icon = {
            "success": "✓", "failed": "✗",
            "skipped": "⊘", "blocked": "⊗",
        }.get(node.status, "?")
        color = {
            "success": Colors.OKGREEN, "failed": Colors.FAIL,
            "skipped": Colors.WARNING, "blocked": Colors.FAIL,
        }.get(node.status, Colors.ENDC)
        print_colored(f"  {icon} {node.id}: {node.summary or node.status}", color)

    if graph.active_sessions:
        print_colored("\n  Active sessions:", Colors.OKCYAN)
        for s in graph.active_sessions:
            print_colored(
                f"    Session {s['session_id']} ({s['type']}) → {s['target']} "
                f"(from {s['source_node']})",
                Colors.OKCYAN,
            )

    print_colored(f"{'='*70}\n", Colors.HEADER)


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# =============================================================================
# CLI — run a graph from a JSON file
# =============================================================================

def main():
    if len(sys.argv) < 2:
        print_colored("Usage: python -m core_agents.orchestrator <graph.json>", Colors.FAIL)
        print_colored("       python -m core_agents.orchestrator --interactive", Colors.FAIL)
        return

    if sys.argv[1] == "--interactive":
        _interactive_mode()
        return

    graph_path = sys.argv[1]
    if not Path(graph_path).exists():
        print_colored(f"Graph file not found: {graph_path}", Colors.FAIL)
        return

    graph = AttackGraph.load(graph_path)
    print_colored(f"Loaded graph: {graph.name}", Colors.OKGREEN)
    print(graph.summary())
    print()

    confirm = input("Execute this graph? [y/N]: ").strip().lower()
    if confirm != "y":
        print_colored("Aborted.", Colors.WARNING)
        return

    run_graph(graph)


def _interactive_mode():
    """Build a simple graph interactively then run it."""
    from examples.disk_wipe_graph import build_disk_wipe_graph

    print_colored("--- Graph-Driven Orchestrator ---", Colors.OKGREEN)

    target_ip = input("[Target IP]: ").strip()
    if not target_ip:
        print_colored("No target IP provided. Exiting.", Colors.FAIL)
        return

    attacker_ip = input("[Attacker IP] (default: 192.168.34.6): ").strip()
    if not attacker_ip:
        attacker_ip = "192.168.34.6"

    # For now, use the disk wipe template
    graph = build_disk_wipe_graph(target_ip=target_ip, attacker_ip=attacker_ip)
    print()
    print(graph.summary())
    print()

    confirm = input("Execute this graph? [y/N]: ").strip().lower()
    if confirm != "y":
        print_colored("Aborted.", Colors.WARNING)
        return

    run_graph(graph)


if __name__ == "__main__":
    main()
