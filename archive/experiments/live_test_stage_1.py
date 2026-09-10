"""
Live test driver for Stage 1.

Runs the CREME disk_wipe graph against Metasploitable 3 with explore=True.
The graph expects a Rails app on port 8181 which MS3 doesn't have, so the
rails_exploit node's edge checks will fail and the replanner will activate.

Stage 1's change: when the replanner proposes an MSF module that doesn't
match recon's detected version, accept it with an advisory warning instead
of returning None.

Pass criteria (inspected from the log file produced by this run):
  - At least one [Replanner] line is present (replanner activated).
  - NO "[Replanner] REJECTED proposal" lines (old hard-block behavior gone).
  - At least one of: "ADVISORY mismatch ... allowing anyway" OR
                    "Module validation OK"
  - At least one replanner-issued node attempts execution (look for
    [Replanner] NEW NODE then [Dispatch] for that node id).
"""

from __future__ import annotations
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.disk_wipe_graph import build_disk_wipe_graph

TARGET_IP = "192.168.34.7"      # Metasploitable 3
ATTACKER_IP = os.getenv("LHOST", "192.168.34.1")    # Kali

if __name__ == "__main__":
    graph = build_disk_wipe_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}")
    print(graph.summary())
    print()
    print(f"Running with explore=True against {TARGET_IP}...")
    run_graph(graph, explore=True)
