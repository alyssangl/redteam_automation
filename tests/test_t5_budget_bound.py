"""T5 (experiment_plan.md §4): the repair budget is honoured; termination by
construction.

Two claims:
  - With B=0 a failed node returns ABANDON (no repair, no grown node).
  - No run exceeds |V0| + B executed nodes.

The bound is a hard loop invariant: _try_replanner grows a node only while
replan_attempts < max_replan_attempts, so grown nodes <= B and total <= |V0| + B.
These tests pin the abandon paths with NO LLM/lab (the guards return before
_replan_from is ever reached). The empirical "no run exceeded the bound" is verified
over the live orphan checkpoints in the T5 data check (max grown = 1, B = 10).

Run:
    python tests/test_t5_budget_bound.py
"""
import sys, os, logging, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core_agents.orchestrator as orch
from core_agents.attack_graph import AttackGraph, AttackNode, NodeStatus

LOG = logging.getLogger("t"); LOG.addHandler(logging.NullHandler())
_CP = os.path.join(tempfile.gettempdir(), "t5_dummy.json")


def _graph():
    g = AttackGraph(name="t", objective="escalate", target_ip="192.168.34.7",
                    attacker_ip="192.168.34.6")
    n = AttackNode(id="esc", label="Esc", agent_type="privesc", tactic="privilege_escalation")
    n.status = NodeStatus.FAILED.value
    g.add_node(n)
    return g


def test_zero_budget_abandons():
    # B=0: the while loop never runs -> no repair, no LLM, ABANDON.
    g = _graph()
    n0 = len(g.nodes)
    new_target, attempts = orch._try_replanner(
        g, "esc", LOG, _CP, replan_attempts=0, max_replan_attempts=0, explore=True)
    assert new_target is None, "B=0 must abandon (no new target)"
    assert attempts == 0
    assert len(g.nodes) == n0, "B=0 must not grow any node"


def test_exhausted_budget_abandons():
    g = _graph()
    n0 = len(g.nodes)
    new_target, attempts = orch._try_replanner(
        g, "esc", LOG, _CP, replan_attempts=10, max_replan_attempts=10, explore=True)
    assert new_target is None
    assert len(g.nodes) == n0


def test_explore_off_abandons():
    g = _graph()
    new_target, _ = orch._try_replanner(
        g, "esc", LOG, _CP, replan_attempts=0, max_replan_attempts=10, explore=False)
    assert new_target is None


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
