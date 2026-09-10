"""
Live test driver for examples/flaw_recon_graph.py.

Intentionally-flawed RECON-ROUTING chain against Metasploitable 3. The
recon -> gain_access edge is gated on a CLOSED port (Jenkins 8484), so recon
succeeds but the planned route is invalid. Expected: the replanner re-routes
to a real initial-access vector (UnrealIRCd 3.2.8.1 backdoor on 6667), lands a
session, and drops the proof-of-compromise file.
"""

from __future__ import annotations
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.flaw_recon_graph import build_flaw_recon_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = os.getenv("LHOST", "192.168.34.1")

if __name__ == "__main__":
    graph = build_flaw_recon_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
