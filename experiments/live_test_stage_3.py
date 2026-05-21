"""
Live test driver for Stage 3.

Same CREME disk_wipe scenario as Stages 1-2, but now with the layer-2 judge
enabled (use_judge=True, default). The judge fires at two trigger points:
  - post_retry: inside _execute_node after each failed attempt
  - post_node:  in run_graph after each node completes

Pass criteria (inspected from the log file produced by this run):
  - At least one [Judge] line appears.
  - Judge fires at both post_retry and post_node triggers at some point.
  - When rails_exploit fails, EITHER:
      (a) judge says 'escalate' and dispatch_node is called <3 times for it
          (proving the judge cut retries short), OR
      (b) judge says 'continue'/'adapt' and the existing retry pattern is preserved
          (proves judge didn't break the flow)
  - The new max_replan_attempts=10 budget appears in Replan attempt log lines.
  - Run completes cleanly (EXECUTION COMPLETE).
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
