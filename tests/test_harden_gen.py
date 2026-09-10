"""Offline tests for the data-generation hardening batch (A1 + B1/B2).

No lab needed — the MSF client / session RPCs are mocked and time is bounded.

A1  — a wedged session RPC read must RETURN within the wall-clock cap, never
      hang forever (the bug: `while elapsed<timeout` counted `elapsed` only on
      healthy reads, so one blocked read froze the whole stage). Also: the
      orchestrator's outer _run_bounded cap fires and scores as a failure.

B1  — a `use <module>` that fails to load must ABORT before set/run. On the
      SHARED persistent console a stale prior module stays armed, so a blind
      `run` would re-fire it and fabricate a spurious "session opened" (the
      confirmed flaw_privesc false success). No `set`/`run` may be issued.

B2  — a PRIVESC node that only sees "session opened" (no uid=0) must NOT be a
      grounded privesc success — it routes to the stage critic instead. A REAL
      root session (uid=0 present) still passes; initial-access is unaffected.

Run: python tests/test_harden_gen.py
"""
import sys, os, types, logging, threading
import time as _time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.metasploit_tools as mt
from tools.metasploit_tools import MetasploitSession
import core_agents.orchestrator as orch
from core_agents.attack_graph import AttackNode

# The read-loop pacing sleeps are irrelevant to these tests — no-op them so the
# wall-clock we measure is dominated by the (real) bounded-read caps, not pacing.
mt.time.sleep = lambda *a, **k: None
orch.time.sleep = lambda *a, **k: None


def _log():
    lg = logging.getLogger("test_harden_gen")
    lg.handlers[:] = [logging.NullHandler()]
    lg.propagate = False
    return lg


LOG = _log()


# =============================================================================
# A1 — bounded session-RPC reads (a wedge returns within the cap, not forever)
# =============================================================================

class _BlockingClient:
    """RPC mock whose *_read calls BLOCK FOREVER (simulates a wedged msfrpcd).
    session.list / *_write return instantly so only the read is the hang point."""
    def __init__(self, stype="shell"):
        self.stype = stype
        self.block = threading.Event()   # never set -> reads block
        self.calls = []

    def call(self, method, args=None):
        self.calls.append(method)
        if method == "session.list":
            return {3: {b"type": self.stype.encode()}}
        if method.endswith("_write"):
            return {}
        if method.endswith("_read"):
            self.block.wait()            # <-- would hang forever without A1
            return {b"data": b""}
        return {}


def _blocking_session(stype="shell"):
    s = MetasploitSession.__new__(MetasploitSession)   # bypass __init__ (connects)
    s.client = _BlockingClient(stype)
    return s


def test_wedged_shell_read_returns_within_cap():
    s = _blocking_session("shell")
    t0 = _time.time()
    out = s.run_session_command("3", "id", timeout=2)   # read_cap floors at 2s
    elapsed = _time.time() - t0
    assert elapsed < 12, f"run_session_command HUNG ({elapsed:.1f}s) — read not bounded"
    assert isinstance(out, str)   # returned SOMETHING rather than blocking forever


def test_wedged_meterpreter_read_returns_within_cap():
    s = _blocking_session("meterpreter")
    t0 = _time.time()
    out = s.run_session_command("3", "id", timeout=2)
    elapsed = _time.time() - t0
    # meterpreter path has a few bounded reads (drain/loop/exit), each ~2s
    assert elapsed < 20, f"run_session_command HUNG ({elapsed:.1f}s) — read not bounded"
    assert isinstance(out, str)


def test_get_session_type_bounded_returns_none_on_wedged_list():
    # a wedged session.list must not hang get_session_type — it returns None
    class _Wedge:
        def __init__(self):
            self.block = threading.Event()
        def call(self, method, args=None):
            self.block.wait()
    s = MetasploitSession.__new__(MetasploitSession)
    s.client = _Wedge()
    # shrink the cap so the test is quick
    s._RPC_READ_CAP = 2
    t0 = _time.time()
    assert s.get_session_type("3") is None
    assert _time.time() - t0 < 8


def test_run_bounded_timeout_sentinel_scores_as_failure():
    # the orchestrator's outer cap (A1b): a call that never finishes -> sentinel,
    # and that sentinel must be caught by the failure scanner (never a false pass).
    ev = threading.Event()   # blocks the worker until we release it below
    try:
        out = orch._run_bounded(
            lambda: ev.wait(),
            timeout=1,
            on_timeout=orch._DIRECT_SESSION_TIMEOUT_MSG,
        )
        assert out == orch._DIRECT_SESSION_TIMEOUT_MSG
        assert orch._command_output_indicates_failure(out)[0] is True
    finally:
        # Release the (non-daemon) executor worker so concurrent.futures' atexit
        # join can't hang the interpreter waiting on a never-returning call.
        ev.set()
        _time.sleep(0.05)


# =============================================================================
# B1 — a failed `use` must ABORT before set/run (no stale-module re-fire)
# =============================================================================

class _RecordingMsf:
    """send_command mock that records every command and replies per prefix."""
    def __init__(self, responses):
        self.responses = responses
        self.commands = []

    def send_command(self, cmd, timeout=120):
        self.commands.append(cmd)
        for prefix, out in self.responses.items():
            if cmd.startswith(prefix):
                return out
        return ""


def _graph_stub(ip="192.168.34.7"):
    return types.SimpleNamespace(target_ip=ip)


# The exact confirmed transcript shape from
# logs/flaw_privesc_192.168.34.7_20260729_131357.log:128-143
_BOGUS_USE = ("[-] No results from search\n"
              "[-] Failed to load module: "
              "exploit/linux/local/this_module_does_not_exist_priv_esc")
_STALE_SET = "[!] Unknown datastore option: SESSION. Did you mean SSLVersion?\nSESSION => 1"
_REFIRED_RUN = ("[*] Started reverse TCP handler on 0.0.0.0:4444\n"
                "[*] command shell session 2 opened on 192.168.34.7:6667")


def test_failed_use_aborts_before_set_and_run():
    msf = _RecordingMsf({"back": "", "use ": _BOGUS_USE,
                         "set ": _STALE_SET, "run": _REFIRED_RUN})
    node = AttackNode(
        id="escalate", label="Escalate (bogus module)",
        agent_type="privesc", tactic="privilege_escalation",
        module="exploit/linux/local/this_module_does_not_exist_priv_esc",
        module_options={"SESSION": "1"},
    )
    preceding = {"gain_access": {"success": True, "session_id": "1",
                                 "session_type": "command_shell", "access_level": "user"}}
    res = orch._execute_msf_module(node, _graph_stub(), LOG, msf, preceding)

    assert res["success"] is False, "a module that failed to load must NOT succeed"
    assert res["failure_category"] == "module_load_failed"
    # The re-fire vector: `run` (and any `set`) must NEVER be issued after use failed.
    assert not any(c == "run" or c.startswith("run ") for c in msf.commands), \
        f"`run` must NOT fire after a failed use — commands={msf.commands}"
    assert not any(c.startswith("set ") for c in msf.commands), \
        f"`set` must NOT fire after a failed use — commands={msf.commands}"
    # The console context was reset (back issued) so nothing stays armed.
    assert "back" in msf.commands


def test_load_failed_transcript_never_yields_success_via_parse():
    # Even if a load-failure transcript reaches _parse_msf_output directly, the
    # bare "session opened" in it must not be scored as a privesc success.
    node = AttackNode(id="escalate", label="x", agent_type="privesc",
                      tactic="privilege_escalation", module="exploit/linux/local/bogus")
    combined = _BOGUS_USE + "\n" + _REFIRED_RUN
    res = orch._parse_msf_output(combined, node, "192.168.34.7", LOG)
    assert res["success"] is False


def test_valid_module_still_runs_set_and_run():
    # regression: a module that loads cleanly must still emit set/run as before
    msf = _RecordingMsf({"back": "", "use ": "", "set ": "OK => 1",
                         "run": "[*] command shell session 1 opened on 192.168.34.7"})
    node = AttackNode(
        id="ga", label="unrealircd", agent_type="exploit", tactic="initial_access",
        module="exploit/unix/irc/unreal_ircd_3281_backdoor",
        module_options={"RHOSTS": "192.168.34.7", "RPORT": "6667"},
    )
    res = orch._execute_msf_module(node, _graph_stub(), LOG, msf, {})
    assert res["success"] is True
    assert any(c.startswith("set ") for c in msf.commands)
    assert any(c == "run" for c in msf.commands)


# =============================================================================
# B2 — a privesc "session opened" without uid=0 is NOT a grounded success
# =============================================================================

def _priv_node():
    return AttackNode(id="escalate", label="x", agent_type="privesc",
                      tactic="privilege_escalation",
                      module="exploit/linux/local/whatever")


def test_privesc_session_without_uid0_is_not_success():
    out = "[*] command shell session 2 opened on 192.168.34.7:6667"
    res = orch._parse_msf_output(out, _priv_node(), "192.168.34.7", LOG)
    assert res["success"] is False, "bare session-opened is not proof of escalation"
    assert res["failure_category"] == "privesc_unverified"
    assert res["session_id"] == "", "a bogus escalated session must not be propagated"


def test_privesc_session_with_uid0_is_success():
    # a REAL local-exploit that opens a root session (uid=0 present) still passes
    out = ("uid=0(root) gid=0(root) groups=0(root)\n"
           "[*] meterpreter session 3 opened on 192.168.34.7")
    res = orch._parse_msf_output(out, _priv_node(), "192.168.34.7", LOG)
    assert res["success"] is True
    assert res["session_id"] == "3"
    assert res["access_level"] == "root"


def test_privesc_tactic_only_also_gated():
    # gate keys off tactic too, not just agent_type
    node = AttackNode(id="e", label="x", agent_type="", tactic="privilege_escalation",
                      module="exploit/linux/local/whatever")
    out = "[*] meterpreter session 4 opened on 192.168.34.7"
    res = orch._parse_msf_output(out, node, "192.168.34.7", LOG)
    assert res["success"] is False


def test_initial_access_session_opened_still_success():
    # non-privesc nodes are UNAFFECTED — a session-opened is a legit success
    node = AttackNode(id="ga", label="x", agent_type="exploit", tactic="initial_access",
                      module="exploit/unix/irc/unreal_ircd_3281_backdoor")
    out = "[*] command shell session 1 opened on 192.168.34.7:6667"
    res = orch._parse_msf_output(out, node, "192.168.34.7", LOG)
    assert res["success"] is True
    assert res["session_id"] == "1"


def test_privesc_use_load_failed_helper():
    assert orch._msf_use_load_failed(_BOGUS_USE) is True
    assert orch._msf_use_load_failed("") is False
    assert orch._msf_use_load_failed("PAYLOAD => cmd/unix/reverse_bash") is False


# =============================================================================
# A4 — end-of-run console cleanup (destroy when connected, no-op otherwise)
# =============================================================================

def test_cleanup_msf_console_noop_when_not_connected():
    # reading _real must NOT trigger a lazy connect; cleanup is a no-op offline
    saved = mt.msf_session._real
    try:
        mt.msf_session._real = None
        orch._cleanup_msf_console(LOG)          # must not raise, must not connect
        assert mt.msf_session._real is None
    finally:
        mt.msf_session._real = saved


def test_cleanup_msf_console_destroys_and_resets_when_connected():
    class _FakeReal:
        def __init__(self): self.destroyed = False
        def cleanup(self): self.destroyed = True
    fake = _FakeReal()
    saved = mt.msf_session._real
    try:
        mt.msf_session._real = fake
        orch._cleanup_msf_console(LOG)
        assert fake.destroyed is True, "the console must be destroyed at end-of-run"
        assert mt.msf_session._real is None, "the lazy wrapper must reset for a fresh reconnect"
    finally:
        mt.msf_session._real = saved


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
