"""Offline tests for the orphan-A capability-loss scenario graph.

orphan-A is the paper's headline scenario: a normal working chain
(recon -> gain_access -> escalate) whose access SESSION is destroyed externally
before privesc runs. These tests check the graph is well-formed and that its
injection contract is structurally sound — specifically that the capability being
destroyed is genuinely PROVIDED by an earlier node, which is what guarantees
`kappa in H` at kill time (smoke test T2's precondition). No lab needed.

Run:
    python tests/test_orphan_a_graph.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from examples.orphan_a_graph import (
    build_orphan_a_graph, KILL_BEFORE_NODE, CAPABILITY_PROVIDER,
)

TARGET, ATTACKER = "192.168.34.7", "192.168.34.6"


def _graph():
    return build_orphan_a_graph(target_ip=TARGET, attacker_ip=ATTACKER)


def test_graph_builds_and_is_well_formed():
    g = _graph()
    assert set(g.nodes) == {"recon", "gain_access", "escalate"}
    # recon is the sole root; escalate is the objective (a leaf).
    assert g.ready_nodes() == ["recon"]
    assert g.root_nodes() == ["recon"]
    # escalate is a privesc node (the objective).
    assert g.get_node("escalate").agent_type == "privesc"


def test_injection_contract_present():
    inj = _graph().metadata["injection"]
    assert inj["type"] == "capability_loss"       # graft, not substitute
    assert inj["capability"] == "session"
    assert inj["kill_before_node"] == KILL_BEFORE_NODE == "escalate"
    assert inj["provided_by_node"] == CAPABILITY_PROVIDER == "gain_access"


def test_destroyed_capability_is_actually_established_first():
    # The whole scenario is only valid if the capability EXISTED before the kill
    # (kappa in H). Structurally: the provider node must precede the kill node on a
    # path, and it must be the node that opens the session (a metasploit exploit).
    g = _graph()
    provider = g.get_node(CAPABILITY_PROVIDER)
    # provider opens a session (initial access via an exploit module).
    assert provider.agent_type == "exploit"
    assert provider.module  # a real lander module is prescribed
    # there is an edge provider -> kill_before_node carrying the session dependency
    outs = [(e.source, e.target) for e in g.outgoing_edges(CAPABILITY_PROVIDER)]
    assert (CAPABILITY_PROVIDER, KILL_BEFORE_NODE) in outs


def test_kill_edge_requires_a_session():
    # The edge into the kill node must depend on session_id — that dependency is
    # exactly the capability the harness destroys.
    g = _graph()
    edge = next(e for e in g.edges
                if e.source == CAPABILITY_PROVIDER and e.target == KILL_BEFORE_NODE)
    fields = [c.field for c in edge.checks]
    assert "session_id" in fields


def test_registry_resolves_orphan_a():
    # run_matrix resolves scenarios by key via ui.registry; orphan_a must be found.
    from ui.registry import resolve_builder
    builder = resolve_builder("orphan_a")
    g = builder(target_ip=TARGET, attacker_ip=ATTACKER)
    assert g.metadata["scenario"] == "orphan_a"


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    import warnings; warnings.filterwarnings("ignore")
    fails = 0
    for t in TESTS:
        try:
            t(); print(f"PASS {t.__name__}")
        except Exception as e:
            fails += 1; print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(TESTS)-fails}/{len(TESTS)} passed")
    sys.exit(1 if fails else 0)
