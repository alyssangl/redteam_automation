"""Offline tests for the P0 direct-path verification fix.

_with_stderr_capture ensures session-command STDERR is captured so the failure
scanner can see "permission denied" / "no such file" (the flaw_impact false
success). Run: python tests/test_direct_verify.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core_agents.orchestrator import _with_stderr_capture, _command_output_indicates_failure


def test_plain_command_gets_stderr_capture():
    assert _with_stderr_capture("cat /root/x") == "cat /root/x 2>&1"
    assert _with_stderr_capture("echo 'hi' > /root/x") == "echo 'hi' > /root/x 2>&1"


def test_already_managed_stderr_untouched():
    assert _with_stderr_capture("find / -perm -4000 2>/dev/null") == "find / -perm -4000 2>/dev/null"
    assert _with_stderr_capture("id 2>&1") == "id 2>&1"


def test_empty_untouched():
    assert _with_stderr_capture("") == ""
    assert _with_stderr_capture("   ") == ""


def test_denied_write_now_detected():
    # the exact flaw_impact case, once stderr is captured
    assert _command_output_indicates_failure("bash: /root/pwned.txt: Permission denied")[0] is True
    assert _command_output_indicates_failure("cat: /root/pwned.txt: No such file or directory")[0] is True


def test_clean_output_is_success():
    assert _command_output_indicates_failure("PWNED via test")[0] is False
    assert _command_output_indicates_failure("")[0] is False


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
