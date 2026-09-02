"""
fault_injection.py — controlled fault injection for the GRAFT eval (plan §3.3).

A scenario graph declares its fault in metadata["injection"]. For the orphan
(capability-loss) scenarios that is an EXTERNAL session kill: after the access node
has opened a session but BEFORE the node that depends on it runs, the harness
destroys that session from the OUTSIDE — the agent has no way to anticipate it
(§3.3), and the capability genuinely existed first (kappa in H) so the run is
testing what we claim.

This is wired as run_graph's `pre_node_hook`: the walker calls the hook just before
each node's feasibility gate, and the hook kills the session right before
`kill_before_node`. The gate then detects the loss and the graft repairs it.

The kill DECISION (`should_kill_before`) is separated from the live MSF ACTION
(`_stop_session`) so the decision is unit-testable with no lab.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional


def _injection(graph) -> dict:
    return (getattr(graph, "metadata", None) or {}).get("injection") or {}


def should_kill_before(graph, node_id: str, already_fired: set) -> bool:
    """Fire iff this graph declares a capability-loss injection targeting THIS node
    and we have not already fired it."""
    inj = _injection(graph)
    return (
        inj.get("type") == "capability_loss"
        and inj.get("kill_before_node") == node_id
        and node_id not in already_fired
    )


def _stop_session(session_id: str, session_type: str, log: logging.Logger) -> None:
    """Destroy a session via MSF RPC so it leaves session.list (the feasibility gate
    then reads the capability as lost). Best-effort; bounded by the RPC client."""
    from tools.metasploit_tools import msf_session
    try:
        msf_session.client.call("session.stop", [str(session_id)])
    except Exception as e:  # noqa: BLE001
        log.warning(f"[inject] session.stop({session_id}) failed: {e}")


def make_session_kill_hook(kill_fn: Optional[Callable] = None) -> Callable:
    """Build a stateful pre_node_hook that performs the declared capability-loss
    kill exactly once. `kill_fn(session_id, session_type, log)` is injectable so
    tests can observe the kill without a lab."""
    fired: set = set()
    kill = kill_fn or _stop_session

    def hook(node_id: str, graph, log: logging.Logger) -> None:
        if not should_kill_before(graph, node_id, fired):
            return
        # Import here so importing this module never pulls in the orchestrator.
        from core_agents.orchestrator import _find_session
        preceding = graph.gather_preceding_findings(node_id)
        sid, stype, level = _find_session(preceding)
        fired.add(node_id)  # fire once regardless of outcome
        if not sid:
            log.warning(f"[inject] {node_id}: capability-loss declared but no session "
                        f"was established to kill — scenario precondition not met")
            return
        inj = _injection(graph)
        log.info(f"[inject] capability_loss: destroying session {sid} ({stype}) "
                 f"BEFORE {node_id} (capability={inj.get('capability')}); "
                 f"the agent cannot anticipate this")
        kill(sid, stype, log)

    return hook
