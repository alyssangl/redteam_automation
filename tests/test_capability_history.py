"""Offline tests for capability history H (GRAFT §3.2).

H is the set of capabilities held at ANY point in a run; the classifier reads it
to tell a LOST capability (in H -> graft) from one NEVER established (not in H ->
re-order). The trustworthy core is `_capabilities_from_findings`: it must derive
capability tokens ONLY from concrete finding fields (session_id / access_level /
new_level / written file), never from prose, and never credit a non-success node.

Run:
    python tests/test_capability_history.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core_agents.orchestrator as orch

cap = orch._capabilities_from_findings


def test_user_session_yields_session_tokens():
    caps = cap({"success": True, "session_id": "1", "access_level": "user"})
    assert "session" in caps
    assert "session@user" in caps
    assert "root" not in caps


def test_root_session_yields_root_token():
    # privesc exposes the escalated level via new_level
    caps = cap({"success": True, "session_id": "3", "new_level": "root"})
    assert {"session", "session@root", "root"} <= caps


def test_sudo_is_not_root():
    caps = cap({"success": True, "session_id": "2", "access_level": "sudo"})
    assert "session@sudo" in caps
    assert "root" not in caps


def test_failed_node_contributes_nothing():
    # even with a session_id, a non-success finding must not enter H
    assert cap({"success": False, "session_id": "1", "access_level": "root"}) == set()


def test_no_session_no_capability():
    assert cap({"success": True, "summary": "scanned ports"}) == set()


def test_unknown_level_omits_level_token():
    caps = cap({"success": True, "session_id": "1", "access_level": "unknown"})
    assert caps == {"session"}


def test_artifact_capability_from_target_file():
    caps = cap({"success": True, "target_file": "/tmp/pwned.txt"})
    assert "artifact:/tmp/pwned.txt" in caps
    # also read from metadata
    caps2 = cap({"success": True, "metadata": {"target_file": "/tmp/x"}})
    assert "artifact:/tmp/x" in caps2


def test_capability_loss_is_expressible():
    # The scenario the paper needs: gain_access established a session (in H); after
    # the harness kills it, escalate needs "session" which is no longer held but IS
    # in H -> classifiable as a capability loss (not a precondition/mis-order).
    H = set()
    H |= cap({"success": True, "session_id": "1", "access_level": "user"})
    assert "session" in H            # kappa was established
    live = set()                     # world state after the external kill
    needed = "session"
    assert needed not in live and needed in H   # => capability loss, graft applies


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
