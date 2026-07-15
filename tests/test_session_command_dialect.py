"""Offline tests — run_session_command speaks the right dialect per session type.

The B3 regression: after _probe_session upgrades a command_shell to meterpreter,
the executor's shell commands (crontab/echo/useradd) were written straight to
session.meterpreter_write — the meterpreter COMMAND INTERPRETER — which rejects
them as "Unknown command: crontab", so persistence silently no-ops.

The fix: on a meterpreter session, run_session_command drops into a channelized
`shell` and runs the command THERE, framing output with the same end-marker trick
as the raw command_shell path. These tests mock the RPC client (no lab) and assert:

  - meterpreter path drops to `shell`, runs the command in it, frames + returns
    only the real output, and exits the channel back to the meterpreter prompt
  - the command_shell path is unchanged (no `shell` drop, marker framing)
  - a meterpreter command with pipes/quotes (echo '...' | crontab -) is written
    to the shell VERBATIM (no escaping mangling)
  - no marker ever arrives -> "(no output)" (never a false success)

Run: python tests/test_session_command_dialect.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.metasploit_tools as mt
from tools.metasploit_tools import MetasploitSession

# time.sleep is used for pacing the read loop — no-op it so tests run instantly.
mt.time.sleep = lambda *a, **k: None

DONE = "__MSF_CMD_DONE_9271__"


class _FakeClient:
    """Scripted RPC mock: fixed session type + a queue of *_read payloads.

    Records every write so tests can assert the dialect (did we drop to `shell`?
    was the command written verbatim?).
    """
    def __init__(self, stype, read_seq):
        self.stype = stype
        self._reads = list(read_seq)
        self.writes = []          # list of (method, payload)

    def call(self, method, args=None):
        if method == "session.list":
            # msgpack gives int/str session keys (never bytes); get_session_type
            # compares str(sid) == str(session_id), so a bytes key would never match.
            return {3: {b"type": self.stype.encode()}}
        if method.endswith("_write"):
            self.writes.append((method, args[1]))
            return {}
        if method.endswith("_read"):
            payload = self._reads.pop(0) if self._reads else ""
            return {b"data": payload.encode()}
        return {}

    def written(self):
        return [p for _, p in self.writes]


def _session(stype, read_seq):
    """A MetasploitSession with a fake client and no live connection."""
    s = MetasploitSession.__new__(MetasploitSession)   # bypass __init__ (which connects)
    s.client = _FakeClient(stype, read_seq)
    return s


def test_meterpreter_drops_to_shell_and_frames_output():
    # reads: clear-leftover, drain-banner, then the framed real output.
    reads = ["", "Process 1 created.\nChannel 1 created.\n",
             f"uid=0(root) gid=0(root)\n{DONE}\n", ""]
    s = _session("meterpreter", reads)
    out = s.run_session_command("3", "id", timeout=5)
    writes = s.client.written()
    assert "shell\n" in writes, f"must drop into a system shell; writes={writes}"
    assert "id\n" in writes, f"the shell command must be written; writes={writes}"
    assert "exit\n" in writes, f"must leave the shell channel; writes={writes}"
    # `shell` must be written BEFORE the command (drop first, then run in it)
    assert writes.index("shell\n") < writes.index("id\n")
    assert out == "uid=0(root) gid=0(root)", repr(out)
    assert DONE not in out, "the end-marker must be stripped from the returned output"


def test_meterpreter_pipe_command_written_verbatim():
    # The whole point: a real persistence command with a pipe + quotes must reach
    # the target shell unmangled (this is what "Unknown command: crontab" broke).
    cmd = "echo '* * * * * date >> /tmp/.hb' | crontab -"
    reads = ["", "banner\n", f"{DONE}\n", ""]
    s = _session("meterpreter", reads)
    s.run_session_command("3", cmd, timeout=5)
    assert cmd + "\n" in s.client.written(), \
        f"pipe/quote command must be written verbatim to the shell; got {s.client.written()}"


def test_meterpreter_no_marker_is_no_output_not_false_success():
    # marker never arrives -> must NOT invent success; returns the sentinel.
    reads = ["", "banner\n"] + [""] * 10
    s = _session("meterpreter", reads)
    out = s.run_session_command("3", "crontab -l", timeout=3)
    assert out == "(no output)", repr(out)


def test_command_shell_path_unchanged_no_shell_drop():
    # command_shell must NOT drop into `shell` — it already IS a shell. It writes the
    # command + marker poke and frames on the marker.
    reads = [f"vagrant\n{DONE}\n"]
    s = _session("shell", reads)
    out = s.run_session_command("3", "whoami", timeout=5)
    writes = s.client.written()
    assert "shell\n" not in writes, f"command_shell must not drop to shell; writes={writes}"
    assert any(w.startswith("whoami") for w in writes), writes
    assert out == "vagrant", repr(out)


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
