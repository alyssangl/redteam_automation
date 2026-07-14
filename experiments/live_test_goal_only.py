"""
Live test driver for examples/goal_only_graph.py.

Goal-only chain: every post-recon node has no module/commands, so the
orchestrator dispatches each to its STAGE SUBAGENT. This is the run that
actually exercises run_exploitation / run_privesc / run_persistence /
run_impact. explore=True + use_judge=True so each subagent operates with its
full capability.
"""

from __future__ import annotations
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.goal_only_graph import build_goal_only_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = os.getenv("LHOST", "192.168.34.1")

if __name__ == "__main__":
    graph = build_goal_only_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
