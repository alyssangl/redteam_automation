"""Offline test: importing modules must NOT open an MSF connection (v8 lazy).

Regression guard for the v8 lazy-MSF refactor. Run:
    python tests/test_lazy_msf.py
"""
import sys, os, io, contextlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_import_does_not_connect():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        import core_agents.orchestrator  # noqa: F401
        import stages.recon  # noqa: F401
        import stages.initial_access  # noqa: F401
        import stages.privesc  # noqa: F401
        import stages.persistence  # noqa: F401
        import stages.impact  # noqa: F401
    assert "Connecting to Metasploit" not in buf.getvalue(), \
        "import opened an MSF connection — not lazy"


def test_msf_session_is_lazy_and_unconnected():
    from tools.metasploit_tools import msf_session
    assert type(msf_session).__name__ == "_LazyMsfSession"
    # _real is a normal instance attr (no __getattr__), so this must NOT connect
    assert msf_session._real is None, "lazy session connected before first use"


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
