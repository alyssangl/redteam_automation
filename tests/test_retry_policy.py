"""Offline tests for the v10 category-aware retry seed (_is_retryable_failure).

No lab needed. Run:
    python tests/test_retry_policy.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core_agents.orchestrator import _is_retryable_failure


def test_timeboxed_escalate_not_retryable():
    f = {"success": False, "technique": "timeout",
         "summary": "Escalation time-boxed at 300s without reaching root."}
    assert _is_retryable_failure(f) is False


def test_fail_exhausted_not_retryable():
    f = {"success": False, "summary": "Attack failed. CRITIC FEEDBACK: CLASSIFICATION: FAIL_EXHAUSTED"}
    assert _is_retryable_failure(f) is False


def test_exhausted_category_not_retryable():
    assert _is_retryable_failure({"success": False, "failure_category": "exhausted"}) is False


def test_session_unusable_not_retryable():
    # a dead / read-zombie session is deterministic -> retrying the same node
    # against the same session just re-aborts; the replanner must re-exploit.
    assert _is_retryable_failure({"success": False, "failure_category": "session_unusable"}) is False


def test_generic_failure_is_retryable():
    f = {"success": False, "failure_category": "generic", "summary": "no session created"}
    assert _is_retryable_failure(f) is True


def test_param_fixable_left_to_judge():
    # incompatible_payload / wrong_targeturi are param-fixable -> still retryable
    # (the judge 'adapt' path changes the param); do NOT short-circuit these.
    assert _is_retryable_failure({"success": False, "failure_category": "incompatible_payload"}) is True
    assert _is_retryable_failure({"success": False, "failure_category": "wrong_targeturi"}) is True


def test_empty_defaults_retryable():
    assert _is_retryable_failure({}) is True


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
