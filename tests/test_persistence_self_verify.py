"""Offline tests for Fix 3 — persistence subagent owns its own verification.

The planner emits an executable VERIFICATION_PLAN (CMD_/EXPECT_ pairs proving
EXECUTION, not just installation), and the verifier honors that plan as its
PRIMARY success criterion instead of imposing a rigid callback-only bar — while
still refusing to call a bare install listing WORKING.

Prompt-contract guard (no lab, no LLM). Run:
    python tests/test_persistence_self_verify.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.persistence as ps


def test_planner_demands_executable_verification():
    p = ps.PLANNER_PROMPT
    assert "CMD_1:" in p and "EXPECT_1:" in p, "planner must emit CMD_/EXPECT_ pairs"
    assert "RUNNING" in p or "EXECUTION" in p, "must demand proof of execution"
    # A mere listing is explicitly disqualified as proof.
    assert "installation alone is NOT proof" in p, "planner missing install!=proof rule"


def test_verifier_honors_the_plan_first():
    v = ps.VERIFIER_PROMPT
    assert "VERIFICATION_PLAN" in v, "verifier must reference the plan's VERIFICATION_PLAN"
    assert "PRIMARY" in v, "the plan must be the PRIMARY criterion"
    assert "FALLBACK" in v, "per-technique strategies demoted to fallback"


def test_verifier_keeps_execution_grounding():
    v = ps.VERIFIER_PROMPT
    # The one non-negotiable: proof must show execution, never a bare install.
    assert "EXECUTING" in v or "EXECUTION" in v, "verifier must still require execution proof"
    assert "never WORKING" in v or "is never WORKING" in v, \
        "an install listing alone must never be WORKING"


def test_verifier_does_not_impose_harsher_bar():
    v = ps.VERIFIER_PROMPT
    assert "harsher bar" in v or "stricter gate" in v, \
        "verifier must be told not to out-strict a plan that already passed"


def test_cron_block_defers_to_plan():
    # The runtime-injected cron context should point at the plan's execution
    # check and accept a single inbound callback as valid proof, not force a
    # full interactive shell.
    src = open(ps.__file__, encoding="utf-8").read()
    assert "single inbound" in src, "cron block must accept a one-off callback as proof"
    assert "Do NOT downgrade a plan whose execution check passed" in src, \
        "cron block must not re-impose a bar over a passing plan"


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
