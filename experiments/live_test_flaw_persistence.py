"""
Live test driver for examples/flaw_persistence_graph.py.

Deliberately-flawed-at-persistence chain against Metasploitable 3. The
gain_access stage lands a real command shell via the UnrealIRCd 3.2.8.1
backdoor on port 6667. The persist stage prescribes a WRONG persistence
module/option that fails direct execution, which (in explore mode) must
trigger the direct->subagent fallback for the persistence stage. The
subagent should establish a real persistence mechanism over the existing
session, after which file_drop writes and verifies a proof file.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.flaw_persistence_graph import build_flaw_persistence_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = "192.168.34.6"

if __name__ == "__main__":
    graph = build_flaw_persistence_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
