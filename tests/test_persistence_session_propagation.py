"""Offline tests — the persistence stage propagates its session downstream.

v16b invariant: a stage holding a live session must surface session_id/session_type
in its findings, or the session orphans downstream. Live regression: after the
grow-technique routing fix, file_drop was finally REACHED but died with
"tool_name=session but no active session in preceding nodes" because
_extract_persistence_findings dropped the session. On success the (probed/possibly
meterpreter-upgraded) session must be propagated; on failure it must NOT (it may be
a corpse that would mislead impact).

No lab. Run: python tests/test_persistence_session_propagation.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.persistence as ps


def test_findings_propagate_session_on_success():
    state = {"critic_verdict": "PASS",
             "persistence_plan": "install a cron job heartbeat to /tmp/.hb",
             "install_result": "cron installed", "verification_result": "STATUS: WORKING",
             "session_id": "14", "session_type": "meterpreter"}
    f = ps._extract_persistence_findings(state)
    assert f["success"] is True
    assert f["session_id"] == "14" and f["session_type"] == "meterpreter", \
        f"success must propagate the (upgraded) session for downstream impact; got {dict(f)}"


def test_findings_no_session_on_failure():
    # A failed persistence node must NOT hand impact a possibly-dead session.
    state = {"critic_verdict": "FAIL", "persistence_plan": "cron",
             "install_result": "", "verification_result": "", "loop_step": 3,
             "session_id": "14", "session_type": "meterpreter"}
    f = ps._extract_persistence_findings(state)
    assert f["success"] is False
    assert f["session_id"] == "" and f["session_type"] == "", \
        "a failed persistence node must not propagate a session"


def test_orchestrator_tracks_propagated_session():
    # The orchestrator only records a session in graph.active_sessions when findings
    # carry a non-empty session_id (orchestrator.py ~L2320). Guard that a successful
    # persistence node's findings satisfy that shape so the session is tracked.
    state = {"critic_verdict": "PASS", "persistence_plan": "cron heartbeat",
             "install_result": "ok", "verification_result": "STATUS: WORKING",
             "session_id": "14", "session_type": "meterpreter"}
    f = ps._extract_persistence_findings(state)
    assert "session_id" in f and f.get("session_id"), \
        "findings must carry a truthy session_id for the orchestrator to track it"


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
