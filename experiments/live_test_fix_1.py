"""
Live test driver for Fix 1 — command failure detection.

Re-runs the CREME disk_wipe graph. Before this fix, replanner-issued
session-command nodes were marked SUCCESS even when their commands
clearly failed (Permission denied, No such file or directory, (no
output) across every command). After this fix, the orchestrator
should mark those nodes FAILED so the replanner gets honest signal.

Pass criteria:
  - Any replanner-issued session-command node that produces
    Permission denied / cannot access / does not exist / etc. output
    is now marked FAILED (not SUCCESS).
  - Conversely, nodes whose commands run cleanly stay marked SUCCESS.
  - Run completes cleanly.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.disk_wipe_graph import build_disk_wipe_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = "192.168.34.6"

if __name__ == "__main__":
    graph = build_disk_wipe_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
