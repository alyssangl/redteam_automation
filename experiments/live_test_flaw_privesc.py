"""
Live test driver for examples/flaw_privesc_graph.py.

Intentionally-flawed-at-privesc chain against Metasploitable 3. gain_access
lands a command shell via the UnrealIRCd 3.2.8.1 backdoor on port 6667. The
escalate node prescribes a bogus/nonexistent local-exploit module on purpose,
so the direct path must fall back to the privesc subagent.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.flaw_privesc_graph import build_flaw_privesc_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = "192.168.34.6"

if __name__ == "__main__":
    graph = build_flaw_privesc_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
