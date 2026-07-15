"""Offline tests — replanner grows the NEXT MITRE technique node.

When stuck at a persistence node, the replanner picks the next AVAILABLE technique
from the catalog menu and grows a goal-only persistence node with it assigned; the
subagent then owns the procedure. It must never re-grow a TRIED technique, and the
menu it sees must mark already-failed techniques.

The LLM is mocked (no lab, no OpenAI). Run:
    python tests/test_replanner_grow_technique.py
"""
import sys, os, logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core_agents.orchestrator as orch
from core_agents.attack_graph import AttackGraph, AttackNode, NodeStatus

LOG = logging.getLogger("test"); LOG.addHandler(logging.NullHandler())


class _FakeResp:
    def __init__(self, content): self.content = content


def _build_graph(persist_status=NodeStatus.FAILED.value, persist_method="cron_job"):
    """gain (SUCCESS, session) -> persist (FAILED, tried cron)."""
    g = AttackGraph(name="t", objective="establish persistence on target",
                    target_ip="192.168.34.7", attacker_ip="192.168.34.6")
    gain = AttackNode(id="gain", label="Gain", agent_type="initial_access",
                      tactic="initial_access")
    gain.status = NodeStatus.SUCCESS.value
    gain.findings = {"session_id": "1", "session_type": "command_shell",
                     "access_level": "user"}
    g.add_node(gain)
    persist = AttackNode(id="persist", label="Persist", agent_type="persistence",
                         tactic="persistence", tool_name="session")
    persist.status = persist_status
    persist.findings = {"method": persist_method, "failure_category": "generic"}
    g.add_node(persist)
    g.connect("gain", "persist")
    return g


def _run_replan(graph, intent_json, capture=None, stuck="persist"):
    """Drive _replan_from with call_llm mocked to return intent_json."""
    def fake_llm(messages=None, system_prompt=None, model_name=None, **kw):
        if capture is not None:
            capture["context"] = messages[0].content
        return _FakeResp(intent_json)
    orig = orch.call_llm
    orch.call_llm = fake_llm
    try:
        return orch._replan_from(graph, stuck, LOG)
    finally:
        orch.call_llm = orig


def test_failed_techniques_reads_method():
    g = _build_graph()
    assert orch._failed_techniques(g, "persistence") == {"cron_job"}


def test_session_context_from_success_node():
    g = _build_graph()
    al, st = orch._current_session_context(g)
    assert st == "command_shell" and al == "user"


def test_menu_injected_marks_cron_tried():
    g = _build_graph()
    cap = {}
    _run_replan(g, '{"action":"grow_technique","technique_id":"T1098.004","rationale":"ssh open"}', cap)
    ctx = cap["context"]
    assert "MITRE TECHNIQUE MENU" in ctx
    assert "cron_job" in ctx and "TRIED" in ctx     # cron already failed
    assert "AVAILABLE" in ctx                        # ssh_key available


def test_grow_technique_adds_assigned_node():
    g = _build_graph()
    before = set(g.nodes)
    new_id = _run_replan(g, '{"action":"grow_technique","technique_id":"T1098.004","rationale":"ssh open"}')
    assert new_id and new_id not in before
    n = g.nodes[new_id]
    assert n.agent_type == "persistence" and n.tactic == "persistence"
    assert n.technique_id == "T1098.004"            # ssh_key assigned
    assert not n.module and not n.commands_to_run    # goal-only -> reaches subagent
    # edge grown from the stuck node
    assert any(e.source == "persist" and e.target == new_id for e in g.edges)


def test_grow_technique_rejects_already_failed():
    g = _build_graph()
    before = set(g.nodes)
    # cron already failed -> must be rejected
    out = _run_replan(g, '{"action":"grow_technique","technique_id":"T1053.003","rationale":"retry cron"}')
    assert out is None
    assert set(g.nodes) == before                    # no node added


def test_grow_technique_rejects_unresolved():
    g = _build_graph()
    out = _run_replan(g, '{"action":"grow_technique","technique_id":"T9999","rationale":"bogus"}')
    assert out is None


# --- V2: walker backtracked — stuck at the PREDECESSOR, persist node FAILED ---

def test_menu_injected_when_stuck_at_predecessor():
    # systemd failed on persist; replanner is stuck at gain (initial_access).
    g = _build_graph(persist_method="systemd_service")
    cap = {}
    _run_replan(g, '{"action":"grow_technique","technique_id":"T1053.003","rationale":"cron"}',
                cap, stuck="gain")
    ctx = cap["context"]
    assert "MITRE TECHNIQUE MENU" in ctx, "menu must appear even when stuck at predecessor"
    assert "systemd_service" in ctx and "TRIED" in ctx
    assert "PRECEDENCE" in ctx


def test_grow_from_predecessor_adds_cron_node():
    g = _build_graph(persist_method="systemd_service")
    before = set(g.nodes)
    new_id = _run_replan(g, '{"action":"grow_technique","technique_id":"T1053.003","rationale":"cron"}',
                         stuck="gain")
    assert new_id and new_id not in before
    n = g.nodes[new_id]
    assert n.tactic == "persistence" and n.technique_id == "T1053.003"
    # grown from the stuck predecessor, which carries the session
    assert any(e.source == "gain" and e.target == new_id for e in g.edges)


def test_failed_techniques_findings_based_not_status_gated():
    # The walker resets a judge_escalate'd node to PENDING but its findings persist.
    # _failed_techniques must still count it (via failure_category + technique_id).
    g = _build_graph(persist_status=NodeStatus.PENDING.value)
    g.nodes["persist"].technique_id = "T1543.002"     # systemd assigned by graph
    g.nodes["persist"].findings = {"failure_category": "technique_infeasible",
                                   "technique_exhausted": True, "method": "systemd_service",
                                   "success": False}
    assert orch._failed_techniques(g, "persistence") == {"systemd_service"}


def test_menu_injects_for_pending_but_failed_persist():
    g = _build_graph(persist_status=NodeStatus.PENDING.value)
    g.nodes["persist"].technique_id = "T1543.002"
    g.nodes["persist"].findings = {"failure_category": "technique_infeasible",
                                   "technique_exhausted": True, "method": "systemd_service",
                                   "success": False}
    cap = {}
    _run_replan(g, '{"action":"grow_technique","technique_id":"T1053.003","rationale":"cron"}',
                cap, stuck="gain")
    assert "MITRE TECHNIQUE MENU" in cap["context"]
    assert "systemd_service" in cap["context"] and "TRIED" in cap["context"]


def test_technique_infeasible_is_not_retryable():
    assert orch._is_retryable_failure({"failure_category": "technique_infeasible"}) is False
    assert orch._is_retryable_failure({"technique_exhausted": True}) is False
    # a generic failure is still retryable
    assert orch._is_retryable_failure({"failure_category": "generic"}) is True


def test_no_menu_when_persistence_already_satisfied():
    # persist SUCCEEDED -> no menu, no growth (don't pile on more persistence)
    g = _build_graph(persist_status=NodeStatus.SUCCESS.value, persist_method="cron_job")
    cap = {}
    out = _run_replan(g, '{"action":"grow_technique","technique_id":"T1098.004","rationale":"x"}',
                      cap, stuck="gain")
    assert "MITRE TECHNIQUE MENU" not in cap["context"]
    assert out is None                      # grow_technique rejected when satisfied


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
