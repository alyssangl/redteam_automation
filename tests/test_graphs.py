"""Offline tests: every example graph builds and has the expected shape.

No lab needed. Run:
    python tests/test_graphs.py
"""
import sys, os, importlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

GRAPHS = {
    "proftpd_modcopy": "build_proftpd_modcopy_graph",
    "unrealircd_backdoor": "build_unrealircd_backdoor_graph",
    "samba_pipename": "build_samba_pipename_graph",
    "continuum_rce": "build_continuum_rce_graph",
    "drupal_drupalgeddon2": "build_drupal_drupalgeddon2_graph",
    "goal_only": "build_goal_only_graph",
    "flawed": "build_flawed_graph",
}
CONVERTED = ["proftpd_modcopy", "unrealircd_backdoor", "samba_pipename",
             "continuum_rce", "drupal_drupalgeddon2"]


def _build(name, fn):
    m = importlib.import_module(f"examples.{name}_graph")
    return getattr(m, fn)("192.168.34.7", "192.168.34.6")


def test_all_build():
    for name, fn in GRAPHS.items():
        g = _build(name, fn)
        assert len(g.nodes) >= 3, f"{name}: too few nodes"
        assert len(g.edges) >= 2, f"{name}: too few edges"
        assert g.ready_nodes(), f"{name}: no ready node"


def test_edges_resolve():
    for name, fn in GRAPHS.items():
        g = _build(name, fn)
        ids = set(g.nodes.keys())
        for e in g.edges:
            assert e.source in ids and e.target in ids, \
                f"{name}: dangling edge {e.source}->{e.target}"


def test_escalate_is_goal_only():
    # converted real-service graphs must have a goal-only escalate node (so it
    # dispatches to run_privesc, not the no-LLM direct path) with max_retries=1
    for name in CONVERTED:
        g = _build(name, GRAPHS[name])
        e = g.nodes.get("escalate")
        assert e is not None, f"{name}: missing escalate node"
        assert e.agent_type == "privesc", f"{name}: escalate agent_type={e.agent_type}"
        assert not e.module and not e.commands_to_run, f"{name}: escalate not goal-only"
        assert e.max_retries == 1, f"{name}: escalate max_retries={e.max_retries}"


def test_no_full_port_scan_hint():
    # recon node hints should not prescribe a full -p- / 0-65535 scan
    for name, fn in GRAPHS.items():
        g = _build(name, fn)
        for n in g.nodes.values():
            for c in (n.commands_to_run or []):
                assert "0-65535" not in c and "-p-" not in c, \
                    f"{name}/{n.id}: full-port-scan hint {c!r}"


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
