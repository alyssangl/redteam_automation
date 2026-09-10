"""Offline tests for the controlled fault-injection hook (GRAFT §3.3, build step 5).

The orphan scenarios kill the access session EXTERNALLY before the dependent node
runs. This is wired as run_graph's pre_node_hook. The kill DECISION is unit-tested
here; the live MSF kill is injected as a stub so no lab is needed.

Run:
    python tests/test_fault_injection.py
"""
import sys, os, logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.fault_injection import should_kill_before, make_session_kill_hook
from examples.orphan_a_graph import build_orphan_a_graph, KILL_BEFORE_NODE
from core_agents.attack_graph import NodeStatus

LOG = logging.getLogger("t"); LOG.addHandler(logging.NullHandler())


def _orphan_graph_with_session():
    """orphan-A with gain_access already succeeded and holding session 1."""
    g = build_orphan_a_graph(target_ip="192.168.34.7", attacker_ip="192.168.34.6")
    gain = g.get_node("gain_access")
    gain.status = NodeStatus.SUCCESS.value
    gain.findings = {"success": True, "session_id": "1", "session_type": "command_shell",
                     "access_level": "user"}
    return g


# --- decision ---------------------------------------------------------------

def test_fires_only_on_the_marked_node():
    g = _orphan_graph_with_session()
    assert should_kill_before(g, KILL_BEFORE_NODE, set()) is True
    assert should_kill_before(g, "recon", set()) is False
    assert should_kill_before(g, "gain_access", set()) is False

def test_does_not_fire_twice():
    g = _orphan_graph_with_session()
    fired = {KILL_BEFORE_NODE}
    assert should_kill_before(g, KILL_BEFORE_NODE, fired) is False

def test_inert_on_non_injection_graph():
    from examples.flaw_persistence_graph import build_flaw_persistence_graph
    g = build_flaw_persistence_graph(target_ip="192.168.34.7", attacker_ip="192.168.34.6")
    # flaw_persistence injects a technique failure, not a capability loss
    for nid in g.nodes:
        assert should_kill_before(g, nid, set()) is False


# --- hook action (kill stubbed) ---------------------------------------------

def test_hook_kills_the_established_session_once():
    g = _orphan_graph_with_session()
    killed = []
    hook = make_session_kill_hook(kill_fn=lambda sid, st, log: killed.append((sid, st)))
    # walking past recon / gain_access does nothing
    hook("recon", g, LOG)
    hook("gain_access", g, LOG)
    assert killed == []
    # arriving at the escalate node kills session 1
    hook(KILL_BEFORE_NODE, g, LOG)
    assert killed == [("1", "command_shell")]
    # firing again is a no-op (once only)
    hook(KILL_BEFORE_NODE, g, LOG)
    assert killed == [("1", "command_shell")]

def test_hook_noops_when_no_session_established():
    # capability-loss declared but the provider never opened a session -> no kill,
    # but the hook still marks itself fired (won't spin).
    g = build_orphan_a_graph(target_ip="192.168.34.7", attacker_ip="192.168.34.6")
    killed = []
    hook = make_session_kill_hook(kill_fn=lambda sid, st, log: killed.append(sid))
    hook(KILL_BEFORE_NODE, g, LOG)
    assert killed == []


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
