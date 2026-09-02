"""Offline tests for the baseline_impact (no-fault) graph — the T1 smoke driver.

T1 needs a no-fault chain whose objective grounds deterministically. This graph is
recon -> gain_access -> file_drop (impact), with NO injection, so the fault hook
never fires. These tests pin that.

Run:
    python tests/test_baseline_impact_graph.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from examples.baseline_impact_graph import build_baseline_impact_graph, PROOF_MARKER
from experiments.fault_injection import should_kill_before

TARGET, ATTACKER = "192.168.34.7", "192.168.34.6"


def _graph():
    return build_baseline_impact_graph(target_ip=TARGET, attacker_ip=ATTACKER)


def test_well_formed_no_fault_chain():
    g = _graph()
    assert set(g.nodes) == {"recon", "gain_access", "file_drop"}
    assert g.ready_nodes() == ["recon"]
    assert g.get_node("file_drop").agent_type == "impact"


def test_no_injection_metadata():
    g = _graph()
    assert "injection" not in g.metadata          # nothing to inject
    # the fault hook must never fire on this graph
    for nid in g.nodes:
        assert should_kill_before(g, nid, set()) is False


def test_objective_is_deterministic_impact():
    obj = _graph().get_node("file_drop")
    assert not obj.commands_to_run and not obj.module   # goal-only -> subagent
    assert PROOF_MARKER in obj.objective


def test_registry_resolves_baseline_impact():
    from ui.registry import resolve_builder
    g = resolve_builder("baseline_impact")(target_ip=TARGET, attacker_ip=ATTACKER)
    assert g.metadata["scenario"] == "baseline_impact"


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
