"""
Live test driver for examples/continuum_rce_graph.py.

Unauthenticated HTTP exploitation chain against Metasploitable 3's
Apache Continuum on the Jetty server at port 8080 (command injection).
Expected to land a command shell via the Continuum command injection.
"""

from __future__ import annotations
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.continuum_rce_graph import build_continuum_rce_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = os.getenv("LHOST", "192.168.34.1")

if __name__ == "__main__":
    graph = build_continuum_rce_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
