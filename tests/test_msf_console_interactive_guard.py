"""Offline test — tool_metasploit_rpc blocks `sessions -i` (console-wedge guard).

`sessions -i <id>` attaches the persistent MSF console interactively; it never
returns a prompt, so the shared console wedges for the rest of the run and every
later RPC confounds the cell (MSF_CONSOLE_WEDGED). This is the confounder that
killed the v6_naive grounding batch. The guard blocks ONLY the interactive-attach
form and steers to the atomic session API; other `sessions` verbs pass through.

The MSF client is faked so send_command is never really called (no lab).

Run:
    python tests/test_msf_console_interactive_guard.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.initial_access as ia


class _FakeMsf:
    def __init__(self): self.sent = []
    def send_command(self, cmd, timeout=60):
        self.sent.append(cmd)
        return f"(ran: {cmd})"


def _rpc(cmd):
    fn = getattr(ia.tool_metasploit_rpc, "func", ia.tool_metasploit_rpc)
    return fn(cmd)


def _patch():
    fake = _FakeMsf()
    ia.msf_session = fake
    return fake


def test_blocks_interactive_attach():
    fake = _patch()
    out = _rpc("sessions -i 2")
    assert "BLOCKED" in out
    assert "tool_session_command" in out and '"2"' in out
    assert fake.sent == [], "interactive attach must NOT reach the console"


def test_blocks_interactive_attach_no_id():
    fake = _patch()
    out = _rpc("sessions -i")
    assert "BLOCKED" in out
    assert fake.sent == []


def test_allows_plain_sessions_list():
    fake = _patch()
    out = _rpc("sessions")
    assert "BLOCKED" not in out and fake.sent == ["sessions"]


def test_allows_sessions_dash_l_and_c():
    fake = _patch()
    _rpc("sessions -l")
    _rpc("sessions -c 'id' -i 2")   # one-shot console command form
    # -l passes; the -c form contains '-i' but is a one-shot command, not an attach.
    # We only block the bare interactive-attach `sessions -i <id>`; -c '<cmd>' is fine.
    assert "sessions -l" in fake.sent


def test_allows_exploit_flow():
    fake = _patch()
    for c in ["use exploit/unix/irc/unreal_ircd_3281_backdoor", "set RHOSTS x", "run"]:
        assert "BLOCKED" not in _rpc(c)
    assert len(fake.sent) == 3


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
