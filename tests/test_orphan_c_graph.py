"""Offline tests for the orphan-C capability-loss scenario (deterministic impact).

orphan-C is the RELIABLE headline scenario: same capability-loss injection as
orphan-A, but the orphaned objective is an impact write+read-back (grounds
deterministically) instead of privesc-to-root (privesc-flaky). These tests check
the graph is well-formed, the injection targets the impact node, the impact node is
goal-only (dispatches to the subagent that resolves the fresh session), and the
registry resolves it. No lab.

Run:
    python tests/test_orphan_c_graph.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from examples.orphan_c_graph import (
    build_orphan_c_graph, KILL_BEFORE_NODE, CAPABILITY_PROVIDER,
    PROOF_MARKER, PROOF_FILE,
)

TARGET, ATTACKER = "192.168.34.7", "192.168.34.6"


def _graph():
    return build_orphan_c_graph(target_ip=TARGET, attacker_ip=ATTACKER)


def test_graph_builds_and_is_well_formed():
    g = _graph()
    assert set(g.nodes) == {"recon", "gain_access", "file_drop"}
    assert g.ready_nodes() == ["recon"]
    assert g.root_nodes() == ["recon"]


def test_objective_is_a_deterministic_impact_node():
    g = _graph()
    obj = g.get_node("file_drop")
    assert obj.agent_type == "impact"
    # GOAL-ONLY: no prescribed commands/module -> dispatches to the impact subagent
    # (whose live-session resolver runs on the fresh grafted session).
    assert not obj.commands_to_run
    assert not obj.module
    # the objective names the exact marker + file so grounding can match the read-back
    assert PROOF_MARKER in obj.objective and PROOF_FILE in obj.objective


def test_injection_targets_the_impact_node():
    inj = _graph().metadata["injection"]
    assert inj["type"] == "capability_loss"
    assert inj["capability"] == "session"
    assert inj["kill_before_node"] == KILL_BEFORE_NODE == "file_drop"
    assert inj["provided_by_node"] == CAPABILITY_PROVIDER == "gain_access"
    assert inj["stage"] == "impact"


def test_capability_provider_opens_a_session_first():
    g = _graph()
    provider = g.get_node(CAPABILITY_PROVIDER)
    assert provider.agent_type == "exploit" and provider.module
    outs = [(e.source, e.target) for e in g.outgoing_edges(CAPABILITY_PROVIDER)]
    assert (CAPABILITY_PROVIDER, KILL_BEFORE_NODE) in outs


def test_kill_edge_requires_a_session():
    g = _graph()
    edge = next(e for e in g.edges
                if e.source == CAPABILITY_PROVIDER and e.target == KILL_BEFORE_NODE)
    assert "session_id" in [c.field for c in edge.checks]


def test_registry_resolves_orphan_c():
    from ui.registry import resolve_builder
    g = resolve_builder("orphan_c")(target_ip=TARGET, attacker_ip=ATTACKER)
    assert g.metadata["scenario"] == "orphan_c"


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
