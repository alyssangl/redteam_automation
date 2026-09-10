"""Offline tests — command_shell -> meterpreter upgrade in _probe_session (B3 fix).

A live but fragile reverse_perl command_shell read-zombies mid-run and breaks cron
heartbeat verification. _probe_session now upgrades a responsive command_shell to a
meterpreter (post/multi/manage/shell_to_meterpreter via the RPC module API) before
handing it to the graph. These tests mock the RPC client so no lab is needed:

  - upgrade produces a NEW meterpreter session   -> returns (new_sid, "meterpreter", upgraded_*)
  - upgrade times out (shell responsive)          -> falls back to the command_shell
  - module launch raises (shell responsive)       -> falls back to the command_shell
  - an already-meterpreter session                -> never attempts an upgrade
  - a READ-ZOMBIE command_shell rescued by upgrade-> returns the new meterpreter (write-driven)
  - a read-zombie whose upgrade also fails         -> fails fast, but only AFTER trying the upgrade

Run: python tests/test_persistence_shell_upgrade.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.persistence as ps


class _FakeModule:
    def __init__(self, on_execute=None, raise_on_execute=False):
        self.opts = {}
        self._on_execute = on_execute
        self._raise = raise_on_execute
        self.executed = False

    def __setitem__(self, k, v):
        self.opts[k] = v

    def execute(self):
        self.executed = True  # record the attempt even if it then raises
        if self._raise:
            raise RuntimeError("module.execute boom")
        if self._on_execute:
            self._on_execute(self.opts)
        return {"job_id": 7, "uuid": "abc"}


class _FakeModules:
    def __init__(self, module):
        self._module = module

    def use(self, mtype, mname):
        assert mtype == "post" and "shell_to_meterpreter" in mname, (mtype, mname)
        return self._module


class _FakeClient:
    """Mock MsfRpcClient: a scripted sequence of session.list snapshots."""
    def __init__(self, session_list_seq, module):
        self._seq = list(session_list_seq)
        self.modules = _FakeModules(module)

    def call(self, method, *args):
        if method == "session.list":
            snap = self._seq[0] if len(self._seq) == 1 else self._seq.pop(0)
            return snap
        return {}


class _FakeMsf:
    def __init__(self, client, shell_responds=True):
        self.client = client
        self._shell_responds = shell_responds
        self._type_map = None  # optional {sid: type}

    def get_session_type(self, sid):
        if self._type_map is not None:
            return self._type_map.get(str(sid))
        # Reflect the current (first) session.list snapshot.
        snap = self.client._seq[0]
        for k, v in snap.items():
            if str(k) == str(sid):
                return v.get("type")
        return None

    def run_session_command(self, sid, cmd, timeout=15):
        # _shell_responds echoes the nonce back iff the shell is responsive.
        if "echo" in cmd and self._shell_responds:
            return cmd.split("echo", 1)[1].strip()
        return "(no output)"


TARGET = "192.168.34.7"


def _snap(**sessions):
    """sessions: sid->type. Host defaults to TARGET."""
    return {sid: {"type": t, "session_host": TARGET} for sid, t in sessions.items()}


def test_upgrade_produces_new_meterpreter():
    # Before: shell session 1. After execute: a new meterpreter session 2 appears.
    before = _snap(**{"1": "shell"})
    after = {"1": {"type": "shell", "session_host": TARGET},
             "2": {"type": "meterpreter", "session_host": TARGET}}
    # session.list order: baseline snapshot (pop), then polls return `after`.
    client = _FakeClient([before, after], _FakeModule())
    ps.msf_session = _FakeMsf(client, shell_responds=True)
    sid, stype, status = ps._probe_session(TARGET, "1", "command_shell")
    assert (sid, stype) == ("2", "meterpreter"), (sid, stype, status)
    assert status == "upgraded_1", status


def test_upgrade_sets_lhost_and_session_options():
    seen = {}
    before = _snap(**{"1": "shell"})
    after = {"1": {"type": "shell", "session_host": TARGET},
             "3": {"type": "meterpreter", "session_host": TARGET}}
    client = _FakeClient([before, after], _FakeModule(on_execute=seen.update))
    ps.msf_session = _FakeMsf(client, shell_responds=True)
    ps._probe_session(TARGET, "1", "command_shell")
    assert seen.get("SESSION") == 1, seen
    assert seen.get("LHOST") == ps.KALI_IP, seen
    assert 4444 <= int(seen.get("LPORT", 0)) <= 4480, seen


def test_upgrade_timeout_falls_back_to_shell():
    # No new meterpreter ever appears -> bounded poll times out, keep the shell.
    before = _snap(**{"1": "shell"})
    client = _FakeClient([before], _FakeModule())  # single snapshot, reused
    ps.msf_session = _FakeMsf(client, shell_responds=True)
    # timeout=0 so the poll loop exits immediately (no hang in the test).
    orig = ps._upgrade_shell_to_meterpreter
    def _fast(t, s, lhost=None, lport=4455, timeout=60):
        return orig(t, s, lhost=lhost, lport=lport, timeout=0)
    ps._upgrade_shell_to_meterpreter = _fast
    try:
        sid, stype, status = ps._probe_session(TARGET, "1", "command_shell")
    finally:
        ps._upgrade_shell_to_meterpreter = orig
    assert (sid, stype) == ("1", "command_shell"), (sid, stype, status)
    assert status == "alive", status


def test_upgrade_launch_error_falls_back_to_shell():
    before = _snap(**{"1": "shell"})
    client = _FakeClient([before], _FakeModule(raise_on_execute=True))
    ps.msf_session = _FakeMsf(client, shell_responds=True)
    sid, stype, status = ps._probe_session(TARGET, "1", "command_shell")
    assert (sid, stype) == ("1", "command_shell"), (sid, stype, status)
    assert status == "alive", status


def test_meterpreter_session_is_not_upgraded():
    before = {"5": {"type": "meterpreter", "session_host": TARGET}}
    # If an upgrade were attempted, module.use would be called; make it explode.
    boom = _FakeModule(raise_on_execute=True)
    client = _FakeClient([before], boom)
    ps.msf_session = _FakeMsf(client, shell_responds=True)
    sid, stype, status = ps._probe_session(TARGET, "5", "meterpreter")
    assert (sid, stype, status) == ("5", "meterpreter", "alive"), (sid, stype, status)


def test_read_zombie_rescued_by_upgrade():
    # KEY case (the live B3 scenario): the command_shell has already zombied by probe
    # time (reads dead), so _shell_responds would be False — but shell_to_meterpreter is
    # WRITE-driven, so the upgrade is attempted anyway and RESCUES it into a meterpreter.
    before = _snap(**{"1": "shell"})
    after = {"1": {"type": "shell", "session_host": TARGET},
             "2": {"type": "meterpreter", "session_host": TARGET}}
    client = _FakeClient([before, after], _FakeModule())
    ps.msf_session = _FakeMsf(client, shell_responds=False)  # zombie reads
    sid, stype, status = ps._probe_session(TARGET, "1", "command_shell")
    assert (sid, stype) == ("2", "meterpreter"), (sid, stype, status)
    assert status == "upgraded_1", status


def test_read_zombie_unrescuable_fails_fast_after_upgrade_attempt():
    # A zombie whose upgrade also fails (module raises) and has no responsive substitute
    # must still abort as unusable — but the upgrade MUST have been attempted first.
    before = _snap(**{"1": "shell"})
    boom = _FakeModule(raise_on_execute=True)
    client = _FakeClient([before], boom)
    ps.msf_session = _FakeMsf(client, shell_responds=False)  # zombie
    sid, stype, status = ps._probe_session(TARGET, "1", "command_shell")
    assert sid is None and stype is None, (sid, stype, status)
    assert boom.executed, "upgrade should be attempted before the zombie fail-fast"


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
