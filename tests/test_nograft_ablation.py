"""Offline tests for the NO-GRAFT ablation (GRAFT headline, build step 4).

NO-GRAFT keeps replan + substitution but disables the capability-loss graft
(revive + re-parent onto a fresh re-exploit). Implemented as a single gated flag:
_session_unusable_present(graph) reads False when EVAL_ENABLE_GRAFT=0, so a
capability failure routes to the technique-substitute path (which cannot restore a
session -> recovery collapses). These tests pin the flag, the ablation label, the
harness wiring, and the gating — no lab.

Run:
    python tests/test_nograft_ablation.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core_agents.eval_flags as flags
import core_agents.orchestrator as orch
from core_agents.attack_graph import AttackGraph, AttackNode, NodeStatus


def _with_env(key, val, fn):
    old = os.environ.get(key)
    if val is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = val
    try:
        return fn()
    finally:
        if old is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = old


def test_graft_flag_defaults_on():
    _with_env("EVAL_ENABLE_GRAFT", None, lambda: (
        None if flags.graft_enabled() else (_ for _ in ()).throw(AssertionError("default off"))))

def test_graft_flag_toggles_off():
    assert _with_env("EVAL_ENABLE_GRAFT", "0", flags.graft_enabled) is False
    assert _with_env("EVAL_ENABLE_GRAFT", "1", flags.graft_enabled) is True

def test_graft_off_is_reported_as_ablation():
    labels = _with_env("EVAL_ENABLE_GRAFT", "0", flags.active_ablations)
    assert "graft" in labels

def test_harness_variant_sets_the_flag():
    from experiments.run_matrix import VARIANTS
    assert "v_nograft" in VARIANTS
    assert VARIANTS["v_nograft"]["env"] == {"EVAL_ENABLE_GRAFT": "0"}


def _graph_with_capability_loss():
    g = AttackGraph(name="t", objective="escalate to root on target",
                    target_ip="192.168.34.7", attacker_ip="192.168.34.6")
    esc = AttackNode(id="esc", label="Esc", agent_type="privesc",
                     tactic="privilege_escalation")
    esc.status = NodeStatus.FAILED.value
    esc.findings = {"failure_category": "session_unusable"}
    g.add_node(esc)
    return g

def test_capability_loss_seen_when_graft_on():
    g = _graph_with_capability_loss()
    assert _with_env("EVAL_ENABLE_GRAFT", "1",
                     lambda: orch._session_unusable_present(g)) is True

def test_capability_loss_hidden_when_graft_off():
    # Same graph, graft disabled -> the graft path is not taken; the failure routes
    # to technique-substitute instead (recovery collapses).
    g = _graph_with_capability_loss()
    assert _with_env("EVAL_ENABLE_GRAFT", "0",
                     lambda: orch._session_unusable_present(g)) is False


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
