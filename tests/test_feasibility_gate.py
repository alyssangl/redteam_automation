"""Offline tests for the feasibility gate F (GRAFT §3.1, build step 3).

F runs BEFORE a node executes and checks its required capabilities are held & live.
A missing capability that was ever held (in H) is a capability LOSS -> graft; one
never established is a precondition. The live session probe is injected so these
run with no lab.

Run:
    python tests/test_feasibility_gate.py
"""
import sys, os, logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core_agents.orchestrator as orch
from core_agents.attack_graph import AttackGraph, AttackNode, NodeStatus

LOG = logging.getLogger("t"); LOG.addHandler(logging.NullHandler())


# --- pre(v): _required_capabilities -----------------------------------------

def test_post_access_stage_requires_session():
    n = AttackNode(id="e", label="Esc", agent_type="privesc", tactic="privilege_escalation")
    assert orch._required_capabilities(n) == {"session"}

def test_recon_and_exploit_require_nothing():
    for atype in ("recon", "exploit", "initial_access"):
        n = AttackNode(id="x", label="x", agent_type=atype, tactic="recon")
        assert orch._required_capabilities(n) == set()

def test_explicit_preconditions_win():
    n = AttackNode(id="e", label="Esc", agent_type="recon", tactic="recon",
                   metadata={"preconditions": ["session", "root"]})
    assert orch._required_capabilities(n) == {"session", "root"}


# --- the decision: capability vs precondition -------------------------------

def test_feasible_when_world_has_required():
    ok, missing, cat = orch._feasibility_decision({"session"}, {"session", "session@user"}, set())
    assert ok and missing == set() and cat == ""

def test_missing_but_in_history_is_capability_loss():
    ok, missing, cat = orch._feasibility_decision({"session"}, set(), {"session"})
    assert ok is False and missing == {"session"} and cat == "capability"

def test_missing_and_never_held_is_precondition():
    ok, missing, cat = orch._feasibility_decision({"session"}, set(), set())
    assert ok is False and cat == "precondition"


# --- world state s: _world_capabilities (probe injected) --------------------

def _preceding_with_session(level="user"):
    return {"gain": {"success": True, "session_id": "1", "access_level": level}}

def test_world_includes_live_session():
    caps = orch._world_capabilities(_preceding_with_session(), lambda sid, st="": True)
    assert "session" in caps and "session@user" in caps

def test_world_excludes_dead_session():
    # probe says the session no longer responds -> not in the live world state
    caps = orch._world_capabilities(_preceding_with_session(), lambda sid, st="": False)
    assert caps == set()

def test_world_holds_session_when_any_predecessor_is_live():
    # REGRESSION (graft loop): after a graft the orphaned node has TWO predecessors
    # — the DEAD original session and the FRESH re-exploit session. The world must
    # still hold `session` via the live one; picking only the dead one loops F=0.
    preceding = {
        "gain": {"success": True, "session_id": "1", "access_level": "user"},   # killed
        "reexploit": {"success": True, "session_id": "2", "access_level": "user"},  # fresh
    }
    alive = lambda sid, st="": sid == "2"   # only the re-exploit session is live
    caps = orch._world_capabilities(preceding, alive)
    assert "session" in caps


# --- integration: _feasibility_gate over a real graph -----------------------

def _graph():
    g = AttackGraph(name="t", objective="escalate", target_ip="192.168.34.7",
                    attacker_ip="192.168.34.6")
    gain = AttackNode(id="gain", label="Gain", agent_type="exploit", tactic="initial_access")
    gain.status = NodeStatus.SUCCESS.value
    gain.findings = {"success": True, "session_id": "1", "access_level": "user"}
    g.add_node(gain)
    esc = AttackNode(id="esc", label="Esc", agent_type="privesc", tactic="privilege_escalation")
    g.add_node(esc)
    g.connect("gain", "esc")
    return g, esc

def test_gate_flags_capability_loss_when_session_dead():
    g, esc = _graph()
    H = {"session", "session@user"}          # session WAS held
    ok, missing, cat = orch._feasibility_gate(
        esc, g, H, LOG, session_alive_fn=lambda sid, st="": False)  # killed
    assert ok is False and cat == "capability" and "session" in missing

def test_gate_passes_when_session_alive():
    g, esc = _graph()
    ok, missing, cat = orch._feasibility_gate(
        esc, g, {"session"}, LOG, session_alive_fn=lambda sid, st="": True)
    assert ok is True and missing == set()


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
