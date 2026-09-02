"""Offline test for T7 (blacklist correctness, experiment_plan.md §3.5).

A CAPABILITY loss (session_unusable / precondition_unmet) must NOT blacklist the
node's technique — the technique was never at fault, and blacklisting it would stop
the revived node from reusing the technique that works. Only a genuine TECHNIQUE
failure writes to the tried set. _failed_techniques must reflect that.

Run:
    python tests/test_blacklist_capability_vs_technique.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core_agents.orchestrator as orch
from core_agents.attack_graph import AttackGraph, AttackNode, NodeStatus


def _graph_with_persist(findings):
    g = AttackGraph(name="t", objective="establish persistence on target",
                    target_ip="192.168.34.7", attacker_ip="192.168.34.6")
    n = AttackNode(id="persist", label="Persist", agent_type="persistence",
                   tactic="persistence", technique_id="T1053.003",
                   technique_name="Scheduled Task/Job: Cron")
    n.status = NodeStatus.FAILED.value
    n.findings = findings
    g.add_node(n)
    return g


def test_capability_loss_does_not_blacklist_technique():
    # session died — a capability loss. The technique (cron) must stay usable.
    g = _graph_with_persist({"failure_category": "session_unusable", "method": "cron_job"})
    assert orch._failed_techniques(g, "persistence") == set(), \
        "a session_unusable (capability) failure must not blacklist the technique"


def test_precondition_unmet_does_not_blacklist():
    g = _graph_with_persist({"failure_category": "precondition_unmet", "method": "cron_job"})
    assert orch._failed_techniques(g, "persistence") == set()


def test_technique_failure_DOES_blacklist():
    # a genuine technique failure MUST blacklist so the replanner grows the next one.
    g = _graph_with_persist({"technique_exhausted": True, "method": "cron_job"})
    assert len(orch._failed_techniques(g, "persistence")) >= 1, \
        "a technique failure must blacklist the tried technique"


def test_module_failure_still_blacklists():
    # a non-capability failure_category (e.g. module_load_failed) is a technique fault
    g = _graph_with_persist({"failure_category": "module_load_failed", "method": "cron_job"})
    assert len(orch._failed_techniques(g, "persistence")) >= 1


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
