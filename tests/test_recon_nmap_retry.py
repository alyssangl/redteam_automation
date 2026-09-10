"""Offline tests for the recon nmap transient-failure retry seam.

The lab target is intermittently unreachable (packet loss), so a single nmap can
spuriously time out / come back empty. recon.py now retries a strictly-bounded
number of times before surfacing the failure. These tests exercise the pure
transient classifier and the retry wrapper with a stubbed run_ssh_command (no lab,
no real sleeping — time.sleep is patched out).

Run:
    python tests/test_recon_nmap_retry.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.recon as recon
from stages.recon import _is_transient_ssh_failure


# --- classifier ---------------------------------------------------------------

def test_timeout_is_transient():
    assert _is_transient_ssh_failure(
        "SSH_TIMEOUT: command exceeded time limit — nmap -Pn ...") is True

def test_ssh_error_is_transient():
    assert _is_transient_ssh_failure("SSH_ERROR [nmap ...]: timed out") is True

def test_host_down_and_empty_are_transient():
    assert _is_transient_ssh_failure("Note: Host seems down.") is True
    assert _is_transient_ssh_failure("") is True
    assert _is_transient_ssh_failure(
        "Command 'nmap' executed successfully but returned NO OUTPUT.") is True

def test_real_scan_output_is_not_transient():
    good = ("Command 'nmap ...' succeeded.\nOutput:\n"
            "22/tcp open ssh OpenSSH 7.9p1\n80/tcp open http")
    assert _is_transient_ssh_failure(good) is False


# --- retry wrapper (stub run_ssh_command; no real sleep) ----------------------

def _patch(monkey_results):
    """Install a stub run_ssh_command returning successive `monkey_results`, and
    a no-op sleep. Returns a call-counter list."""
    calls = []
    it = iter(monkey_results)
    def fake_run(cmd, timeout=recon.RECON_SSH_TIMEOUT):
        calls.append(cmd)
        try:
            return next(it)
        except StopIteration:
            return monkey_results[-1]
    recon.run_ssh_command = fake_run
    recon.time.sleep = lambda *_a, **_k: None
    return calls


def test_retry_rides_out_a_transient_blip():
    # one timeout then a good result -> wrapper returns the good result.
    orig_run, orig_sleep = recon.run_ssh_command, recon.time.sleep
    try:
        calls = _patch([
            "SSH_TIMEOUT: command exceeded time limit — nmap",
            "Command 'nmap' succeeded.\nOutput:\n22/tcp open ssh",
        ])
        out = recon.run_ssh_command_with_retry("nmap -Pn target", max_retries=2, retry_sleep=0)
        assert "succeeded" in out and "22/tcp" in out
        assert len(calls) == 2   # one retry consumed
    finally:
        recon.run_ssh_command, recon.time.sleep = orig_run, orig_sleep


def test_retry_is_bounded_and_returns_last_error():
    # all attempts transient -> stop after max_retries+1 calls, return last result.
    orig_run, orig_sleep = recon.run_ssh_command, recon.time.sleep
    try:
        calls = _patch(["SSH_TIMEOUT: blip"] * 10)
        out = recon.run_ssh_command_with_retry("nmap -Pn target", max_retries=2, retry_sleep=0)
        assert "SSH_TIMEOUT" in out
        assert len(calls) == 3   # 1 initial + 2 retries, never unbounded
    finally:
        recon.run_ssh_command, recon.time.sleep = orig_run, orig_sleep


def test_no_retry_when_first_attempt_is_clean():
    orig_run, orig_sleep = recon.run_ssh_command, recon.time.sleep
    try:
        calls = _patch(["Command 'nmap' succeeded.\nOutput:\n22/tcp open ssh"])
        out = recon.run_ssh_command_with_retry("nmap -Pn target", max_retries=2, retry_sleep=0)
        assert "succeeded" in out
        assert len(calls) == 1   # no wasted retries on a good scan
    finally:
        recon.run_ssh_command, recon.time.sleep = orig_run, orig_sleep


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
