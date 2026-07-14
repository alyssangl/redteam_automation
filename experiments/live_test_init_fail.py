"""
Live test driver for examples/disk_wipe_init_fail_graph.py.

This graph is designed to fail at ssh_bruteforce (uses root/root which MS3
rejects). The replanner must recover by gaining access some other way --
either alternative credentials or an alternative initial-access exploit --
in order to reach privesc_verify + file_drop.

Crucially, the right behavior here is:
  - DO NOT use new_edge to privesc_verify or file_drop (they need a session;
    preconditions_met should be False because no session exists)
  - DO propose a new_node / use_module that actually gains access

If the replanner instead skips to privesc_verify/file_drop, those nodes will
fail (no session), exposing the goal-dropping concern.
"""

from __future__ import annotations
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.disk_wipe_init_fail_graph import build_init_fail_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = os.getenv("LHOST", "192.168.34.1")

if __name__ == "__main__":
    graph = build_init_fail_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
