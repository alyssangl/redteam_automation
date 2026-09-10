"""Offline tests — impact session probe RETRIES a just-opened (unsettled) shell.

A freshly re-provisioned reverse shell (e.g. from a graft) often answers the FIRST
echo empty because it has not settled, then reads fine a moment later. A single
probe would false-declare it a read-zombie and abort the whole re-provisioned run.
_shell_responds now retries with a short settle between attempts. These tests stub
the bounded RPC call and no-op the sleep — no lab, no real waiting.

Run:
    python tests/test_impact_probe_retry.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.impact as impact

_NONCE = impact._ALIVE_PROBE_NONCE


def _patch(outputs):
    """Make _run_with_timeout return successive `outputs`; no-op the settle sleep.
    Returns a call-counter list."""
    calls = []
    it = iter(outputs)
    def fake(fn, args=(), kwargs=None, timeout=20, on_timeout=""):
        calls.append(args)
        try:
            return next(it)
        except StopIteration:
            return outputs[-1]
    impact._run_with_timeout = fake
    impact.time.sleep = lambda *a, **k: None
    return calls


def test_settles_then_responds():
    orig_run, orig_sleep = impact._run_with_timeout, impact.time.sleep
    try:
        # first two reads empty (unsettled), third echoes back -> alive
        calls = _patch(["", "", f"echo {_NONCE}\n{_NONCE}"])
        assert impact._shell_responds("2", attempts=3, settle=0) is True
        assert len(calls) == 3   # it retried past the empty reads
    finally:
        impact._run_with_timeout, impact.time.sleep = orig_run, orig_sleep


def test_first_try_short_circuits():
    orig_run, orig_sleep = impact._run_with_timeout, impact.time.sleep
    try:
        calls = _patch([f"{_NONCE}"])
        assert impact._shell_responds("2", attempts=3, settle=0) is True
        assert len(calls) == 1   # no wasted retries when it answers immediately
    finally:
        impact._run_with_timeout, impact.time.sleep = orig_run, orig_sleep


def test_genuinely_dead_shell_fails_bounded():
    orig_run, orig_sleep = impact._run_with_timeout, impact.time.sleep
    try:
        calls = _patch(["", "", "", "", ""])   # never echoes back
        assert impact._shell_responds("2", attempts=3, settle=0) is False
        assert len(calls) == 3   # bounded to `attempts`, never unbounded
    finally:
        impact._run_with_timeout, impact.time.sleep = orig_run, orig_sleep


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
