"""
Offline correctness test for Fix 1 — command failure detection.

Verifies that the orchestrator now marks a node FAILED when its
session/SSH commands clearly failed (Permission denied, No such file
or directory, etc.) — instead of the previous "any output = success"
behaviour that caused multiple Stage 1-3 false positives.

Also verifies that legitimately-quiet successful commands (mkdir,
chmod, echo > file) are NOT flagged as failures.

Run: python experiments/test_fix_1_success_detection.py
"""

from __future__ import annotations

import logging
import sys
import types
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ---- Prevent import-time MSF RPC connection ---------------------------------
_fake_msf = types.ModuleType("tools.metasploit_tools")

class _FakeMsfSession:
    def send_command(self, *a, **kw): return ""
    def run_session_command(self, *a, **kw): return ""

_fake_msf.msf_session = _FakeMsfSession()
_fake_msf.MetasploitSession = lambda *a, **kw: _FakeMsfSession()
_fake_msf.tool_session_command = lambda session_id, command: ""
sys.modules["tools.metasploit_tools"] = _fake_msf
# -----------------------------------------------------------------------------

from core_agents.attack_graph import AttackNode
import core_agents.orchestrator as orch


PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
results = []


def check(label: str, cond: bool, detail: str = ""):
    icon = PASS if cond else FAIL
    print(f"  {icon} {label}" + (f" -- {detail}" if detail else ""))
    results.append((label, cond))


def make_logger():
    buf = StringIO()
    log = logging.getLogger(f"fix1_{id(buf)}")
    log.handlers.clear()
    log.setLevel(logging.DEBUG)
    h = logging.StreamHandler(buf)
    h.setLevel(logging.DEBUG)
    log.addHandler(h)
    log.propagate = False
    return log, buf


# -----------------------------------------------------------------------------
# Test 1 — _command_output_indicates_failure recognises known bad outputs
# -----------------------------------------------------------------------------

def test_failure_phrases_detected():
    print("\n[Test 1] _command_output_indicates_failure on known-bad outputs")

    # Reproductions of the actual outputs that caused false-positive successes
    # in earlier live runs (verbatim from Stage 1 log).
    bad_outputs = [
        ("-bash: line 1: /etc/init.d/persistent_backdoor: Permission denied",
         "permission denied"),
        ("chmod: cannot access ‘/etc/init.d/persistent_backdoor’: "
         "No such file or directory",
         "no such file or directory"),
        ("update-rc.d: /etc/init.d/persistent_backdoor: file does not exist",
         "does not exist"),
        ("connect to 192.168.0.1 port 22: Connection refused",
         "connection refused"),
        ("bash: foo: command not found",
         "command not found"),
        # Both "cannot access" and "operation not permitted" match — first in
        # the indicator list wins. The point is that *some* phrase fires.
        ("mkdir: cannot access '/root/foo': Operation not permitted",
         "cannot access"),
        ("Command 'nmap -A 1.2.3.4' failed (Exit Code: 1).\nError:\nXX",
         "(exit code:"),
        ("SSH Connection/Execution Error: timed out",
         "ssh connection/execution error"),
    ]

    for output, expected_phrase in bad_outputs:
        is_fail, matched = orch._command_output_indicates_failure(output)
        check(
            f"  detects: {output[:50]}...",
            is_fail and matched == expected_phrase,
            detail=f"matched={matched!r}",
        )


# -----------------------------------------------------------------------------
# Test 2 — legitimate successful outputs are NOT flagged
# -----------------------------------------------------------------------------

def test_legitimate_outputs_pass():
    print("\n[Test 2] _command_output_indicates_failure spares legit outputs")

    good_outputs = [
        "uid=0(root) gid=0(root) groups=0(root)",        # id
        "root:x:0:0:root:/root:/bin/bash\n...",           # cat /etc/passwd
        "",                                               # empty
        "(no output)",                                    # silent success
        "drwxr-xr-x 2 root root 4096 Jan  1 00:00 /tmp", # ls
        "Hello, World!",                                  # echo
        "1 file copied",                                  # cp success message
    ]

    for output in good_outputs:
        is_fail, matched = orch._command_output_indicates_failure(output)
        check(f"  spares: {output[:40]!r}",
              not is_fail, detail=f"matched={matched!r}")


# -----------------------------------------------------------------------------
# Test 3 — _execute_session_commands marks node FAILED on bad output
# -----------------------------------------------------------------------------

def test_session_executor_catches_failure():
    print("\n[Test 3] _execute_session_commands flags Permission denied as FAILED")

    class FakeSession:
        """Returns Stage 1's actual bad output sequence."""
        def __init__(self):
            self.calls = []
        def run_session_command(self, sid, cmd, timeout=30):
            self.calls.append(cmd)
            return "-bash: line 1: /etc/init.d/persistent_backdoor: Permission denied"

    node = AttackNode(
        id="x", label="x", agent_type="impact", tool_name="session",
        commands_to_run=["echo foo > /etc/init.d/persistent_backdoor"],
        max_retries=1,
    )
    log, _ = make_logger()
    fake = FakeSession()

    result = orch._execute_session_commands(node, log, fake, "1")

    check("success=False", result["success"] is False)
    check("summary mentions the failure", "permission denied" in result["summary"].lower(),
          detail=f"summary={result['summary']!r}")
    check("CommandRecord stored", len(node.commands) == 1)
    check("output preserved on record", "Permission denied" in node.commands[0].output)


# -----------------------------------------------------------------------------
# Test 4 — _execute_session_commands keeps SUCCESS on silent legit commands
# -----------------------------------------------------------------------------

def test_session_executor_keeps_silent_success():
    print("\n[Test 4] _execute_session_commands keeps success on quiet commands")

    class FakeSession:
        def run_session_command(self, sid, cmd, timeout=30):
            return "(no output)"

    node = AttackNode(
        id="x", label="x", agent_type="impact", tool_name="session",
        commands_to_run=["mkdir /tmp/foo", "chmod 700 /tmp/foo"],
        max_retries=1,
    )
    log, _ = make_logger()
    result = orch._execute_session_commands(node, log, FakeSession(), "1")

    check("success=True (no failure phrases)", result["success"] is True)
    check("summary is positive",
          "Executed 2 command(s)" in result["summary"])


# -----------------------------------------------------------------------------
# Test 5 — _execute_ssh_commands also wired up correctly
# -----------------------------------------------------------------------------

def test_ssh_executor_uses_helper():
    print("\n[Test 5] _execute_ssh_commands marks failure on bad SSH output")

    node = AttackNode(
        id="y", label="y", agent_type="exploit", tool_name="ssh",
        commands_to_run=["nmap -invalid 1.2.3.4"],
        max_retries=1,
    )
    log, _ = make_logger()

    # Monkey-patch run_ssh_command to return a wrapped failure
    orig = orch.run_ssh_command
    orch.run_ssh_command = lambda cmd: (
        "Command 'nmap -invalid 1.2.3.4' failed (Exit Code: 1).\n"
        "Error:\nnmap: unrecognized option '--invalid'"
    )
    try:
        result = orch._execute_ssh_commands(node, log)
    finally:
        orch.run_ssh_command = orig

    check("success=False", result["success"] is False)
    check("summary explains the failure",
          "(exit code:" in result["summary"].lower(),
          detail=f"summary={result['summary']!r}")


# -----------------------------------------------------------------------------
# Test 6 — first failing command stops the scan; later commands not consulted
# -----------------------------------------------------------------------------

def test_first_failure_wins():
    print("\n[Test 6] First failing command short-circuits the success verdict")

    class FakeSession:
        def __init__(self):
            self.i = 0
            self.outs = [
                "uid=0(root) gid=0(root)",                # cmd 1 OK
                "cat: /etc/shadow: Permission denied",    # cmd 2 FAIL
                "this output is ignored after",           # cmd 3 — runs but we still flag
            ]
        def run_session_command(self, sid, cmd, timeout=30):
            out = self.outs[self.i]; self.i += 1
            return out

    node = AttackNode(
        id="z", label="z", agent_type="impact", tool_name="session",
        commands_to_run=["id", "cat /etc/shadow", "echo done"],
        max_retries=1,
    )
    log, _ = make_logger()
    result = orch._execute_session_commands(node, log, FakeSession(), "1")

    check("success=False (Permission denied in cmd 2)",
          result["success"] is False)
    check("summary names the failing command (cat /etc/shadow)",
          "/etc/shadow" in result["summary"],
          detail=f"summary={result['summary']!r}")
    # All commands DID get executed (we don't short-circuit on first failure
    # — we just verdict failure once any command failed).
    check("all 3 commands still executed (record kept)",
          len(node.commands) == 3)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Fix 1 — command failure detection — offline tests")
    print("=" * 70)

    test_failure_phrases_detected()
    test_legitimate_outputs_pass()
    test_session_executor_catches_failure()
    test_session_executor_keeps_silent_success()
    test_ssh_executor_uses_helper()
    test_first_failure_wins()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print()
    print("=" * 70)
    if passed == total:
        print(f"  ALL {total} CHECKS PASSED")
        sys.exit(0)
    else:
        print(f"  {passed}/{total} checks passed -- {total - passed} FAILED")
        sys.exit(1)
