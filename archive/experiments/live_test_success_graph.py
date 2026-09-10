"""
Multi-step baseline live test.

Runs the existing examples/disk_wipe_success_graph.py — a 6-node kill chain
designed deterministically for Metasploitable 3 (recon → ssh brute → privesc
verify → SSH key persist → cron persist → file drop). No replanner needed,
every node has a clear path forward.

Run with explore=False / use_judge=False — we want to see the executor walk
the planned graph cleanly, with no LLM in the loop except inside the
recon/exploit stage subagents.

Expected outcome: 6/6 nodes succeed, EXECUTION COMPLETE with success rate 100%.
"""

from __future__ import annotations
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.disk_wipe_success_graph import build_success_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = os.getenv("LHOST", "192.168.34.1")

if __name__ == "__main__":
    graph = build_success_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running BASELINE (explore=False, use_judge=False) against {TARGET_IP}...")
    run_graph(graph, explore=False, use_judge=False)
