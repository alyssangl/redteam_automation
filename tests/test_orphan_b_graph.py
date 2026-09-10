"""Offline tests for the orphan-B capability-loss scenario (persistence placement).

orphan-B is the SECOND placement of the capability-loss graft: the session is
killed one stage earlier than orphan-C — before PERSISTENCE, not before impact —
so the orphaned node is non-terminal and the graft must re-parent a two-node
subgraph (persist -> file_drop). These tests check the graph is well-formed, the
injection targets the persistence node, the orphaned persist node is goal-only
(dispatches to the subagent that resolves the fresh session), and — crucially —
that the DEEPEST objective is an INDEPENDENTLY-groundable impact node, not the
persistence self-report (persistence grounding is findings-derived, C5). No lab.

Run:
    python tests/test_orphan_b_graph.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from examples.orphan_b_graph import (
    build_orphan_b_graph, KILL_BEFORE_NODE, CAPABILITY_PROVIDER,
    PROOF_MARKER, PROOF_FILE,
)

TARGET, ATTACKER = "192.168.34.7", "192.168.34.6"


def _graph():
    return build_orphan_b_graph(target_ip=TARGET, attacker_ip=ATTACKER)


def test_graph_builds_and_is_well_formed():
    g = _graph()
    assert set(g.nodes) == {"recon", "gain_access", "persist", "file_drop"}
    assert g.ready_nodes() == ["recon"]
    assert g.root_nodes() == ["recon"]


def test_injection_targets_the_persistence_node():
    inj = _graph().metadata["injection"]
    assert inj["type"] == "capability_loss"
    assert inj["capability"] == "session"
    assert inj["kill_before_node"] == KILL_BEFORE_NODE == "persist"
    assert inj["provided_by_node"] == CAPABILITY_PROVIDER == "gain_access"
    assert inj["stage"] == "persistence"


def test_orphaned_node_is_goal_only_persistence():
    g = _graph()
    persist = g.get_node("persist")
    assert persist.agent_type == "persistence"
    # GOAL-ONLY: no prescribed commands/module -> dispatches to the persistence
    # subagent (whose live-session resolver runs on the fresh grafted session).
    assert not persist.commands_to_run
    assert not persist.module


def test_objective_is_an_independently_groundable_impact_node():
    """The recovered objective must ground INDEPENDENTLY. persistence grounding is
    self-report (parse_eval C5), so the deepest objective is an impact read-back —
    the same independent proof orphan-C uses — not the persistence claim."""
    g = _graph()
    # _objective_node priority puts impact above persistence, so file_drop is scored.
    obj = g.get_node("file_drop")
    assert obj.agent_type == "impact"
    assert not obj.commands_to_run and not obj.module  # goal-only -> impact subagent
    assert PROOF_MARKER in obj.objective and PROOF_FILE in obj.objective


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


def test_orphaned_node_is_non_terminal():
    """The distinct thing orphan-B exercises: the orphaned node has a downstream, so
    the graft must re-parent a subgraph, not a single leaf."""
    g = _graph()
    outs = [(e.source, e.target) for e in g.outgoing_edges(KILL_BEFORE_NODE)]
    assert (KILL_BEFORE_NODE, "file_drop") in outs


def test_registry_resolves_orphan_b():
    from ui.registry import resolve_builder
    g = resolve_builder("orphan_b")(target_ip=TARGET, attacker_ip=ATTACKER)
    assert g.metadata["scenario"] == "orphan_b"


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
