"""
Example Attack Graph: GOAL-ONLY chain (Metasploitable 3)

Unlike the other example graphs, every post-recon node here has NO module and
NO commands_to_run — only an agent_type + a goal/objective. This forces the
orchestrator to dispatch each node to its STAGE SUBAGENT (run_exploitation,
run_privesc, run_persistence, run_impact) instead of the no-LLM direct path
(see orchestrator.py: direct execution is only taken when a node has a module
or commands_to_run). It is therefore the test that actually exercises the
refined stage subagents, and it embodies the design goal of "tight scope, broad
tools/prompts": each stage must use its full capability to achieve its goal on
its own.

Chain (all goal-only):
  recon       — discover the attack surface
  gain_access — open a session by any working method
  escalate    — escalate privileges on that session
  persist     — establish a persistence mechanism
  impact      — write + verify a proof-of-compromise file
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_goal_only_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Fully compromise the Metasploitable 3 target: discover its "
                  "services, gain an initial session by any effective method, "
                  "escalate to root, establish persistence, and drop a verified "
                  "proof-of-compromise file. Each stage must decide HOW on its "
                  "own — no modules or commands are prescribed.",
        target_ip=target_ip,
        name=f"goal_only_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Goal-only chain that forces every stage through its subagent.",
        metadata={"scenario": "goal_only", "target_type": "metasploitable3"},
    )

    graph.add_node(AttackNode(
        id="recon",
        label="Discover Attack Surface",
        tactic=Tactic.RECONNAISSANCE.value,
        technique_id="T1046",
        technique_name="Network Service Discovery",
        agent_type="recon",
        goal="Map the target's open services and versions",
        objective=f"Discover the open ports, services and versions on {target_ip}.",
        target_ip=target_ip,
        max_retries=2,
        tags=["recon", "goal_only"],
    ))

    graph.add_node(AttackNode(
        id="gain_access",
        label="Gain Initial Access",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Open a shell or meterpreter session on the target",
        objective=f"Gain an initial session on {target_ip} by choosing and "
                  f"running whatever exploit or credential attack is most likely "
                  f"to work against the discovered services. Customize all "
                  f"parameters (RHOSTS, LHOST={attacker_ip}, LPORT).",
        target_ip=target_ip,
        max_retries=4,
        tags=["initial_access", "goal_only"],
    ))

    graph.add_node(AttackNode(
        id="escalate",
        label="Escalate Privileges",
        tactic=Tactic.PRIVILEGE_ESCALATION.value,
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        agent_type="privesc",
        goal="Escalate the session to root",
        objective="From the existing session, enumerate and exploit any viable "
                  "privilege-escalation vector to reach root (sudo, SUID, kernel, "
                  "cron, capabilities, etc.).",
        target_ip=target_ip,
        max_retries=4,
        tags=["privesc", "goal_only"],
    ))

    graph.add_node(AttackNode(
        id="persist",
        label="Establish Persistence",
        tactic=Tactic.PERSISTENCE.value,
        technique_id="T1098.004",
        technique_name="Account Manipulation: SSH Authorized Keys",
        agent_type="persistence",
        goal="Install a persistence mechanism that survives reconnection",
        objective="Establish a reliable persistence mechanism on the target via "
                  "the session (e.g. authorized_keys, cron, service) and verify "
                  "it is in place.",
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
        objective="Write a proof-of-compromise file to /tmp/pwned_goalonly.txt "
                  "via the session, then read it back to verify the write "
                  "succeeded.",
        target_ip=target_ip,
        max_retries=3,
        tags=["impact", "goal_only"],
    ))

    # ---- edges: each gated on the previous stage's findings ----
    graph.connect(
        "recon", "gain_access",
        checks=[EdgeCheck(field="success", operator="equals", expected="True",
                          description="Recon produced usable service data")],
        evidence="Recon mapped the attack surface",
        rationale="Use the discovered services to choose an access vector",
    )
    graph.connect(
        "gain_access", "escalate",
        checks=[EdgeCheck(field="session_id", operator="exists",
                          description="A session was opened")],
        evidence="Initial session established",
        rationale="Escalate privileges on the new session",
    )
    graph.connect(
        "escalate", "persist",
        checks=[EdgeCheck(field="success", operator="equals", expected="True",
                          description="Privilege escalation succeeded")],
        evidence="Higher privilege obtained",
        rationale="Establish persistence with elevated privilege",
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
    graph = build_goal_only_graph(target_ip="192.168.34.7", attacker_ip="192.168.34.6")
    print(graph.summary())
    out_path = "examples/goal_only_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")
    loaded = AttackGraph.load(out_path)
    print(f"Reloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
