"""
Live test driver for Stage 2.

Runs the CREME disk_wipe graph against Metasploitable 3 with explore=True
(same scenario as Stage 1 — rails_exploit fails, replanner activates).

Stage 2's change: the replan context now includes the full raw nmap output
and the last 3 CommandRecord output tails — not just the structured findings
dict with raw_nmap stripped.

Pass criteria (inspected from the log file produced by this run):
  - At least one [Replanner] line is present.
  - The DEBUG context dump for the replan contains:
      * "RECENT COMMAND OUTPUT" section header
      * "raw_nmap_output" key (was previously stripped)
      * At least one command's output_tail with real bytes from the run
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
    print(f"Running with explore=True against {TARGET_IP}...")
    run_graph(graph, explore=True)
