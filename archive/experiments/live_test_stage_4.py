"""
Live test driver for Stage 4.

Same CREME disk_wipe scenario. The replanner now emits tiny intents
{action, target_hint, label?, goal?, rationale}; orchestrator expands
them into full AttackNodes locally (RHOSTS/LHOST/LPORT/RPORT defaulted
from graph context).
import os

Pass criteria (inspected from the log):
  - At least one [Replanner] line.
  - The replanner LLM emission has a small JSON shape (~5 fields), not
    the previous ~15-field verbose payload.
  - At least one NEW NODE is created via the expansion path (its tags
    will include 'intent_expanded' once persisted via checkpoint).
  - For use_module proposals: the resulting node has RHOSTS == target_ip,
    LHOST == attacker_ip, RPORT set when known.
  - Run completes cleanly.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.disk_wipe_graph import build_disk_wipe_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = os.getenv("LHOST", "192.168.34.1")

if __name__ == "__main__":
    graph = build_disk_wipe_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
