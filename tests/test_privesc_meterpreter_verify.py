"""Offline tests for v16c — meterpreter-aware ground-truth privilege check.

_direct_priv_check must probe a meterpreter session with `getuid` (not `id`,
which meterpreter rejects), so a rooted kernel-exploit session is recognised
instead of falsely FAILed. command_shell sessions still use `id`.

No lab needed. Run: python tests/test_privesc_meterpreter_verify.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.privesc as pe

pe.time.sleep = lambda *a, **k: None  # no real waits in the retry path


class _FakeMsf:
    def __init__(self, stype):
        self._stype = stype
    def get_session_type(self, sid):
        return self._stype


def test_meterpreter_uses_getuid():
    pe.msf_session = _FakeMsf("meterpreter")
    calls = []
    pe._session_command_capped = lambda sid, cmd, timeout=15: (
        calls.append((sid, cmd)) or "Server username: root")
    out = pe._direct_priv_check("7")
    assert calls == [("7", "getuid")], calls
    assert out == "[meterpreter getuid] Server username: root", out


def test_command_shell_uses_id():
    pe.msf_session = _FakeMsf("shell")
    calls = []
    pe._session_command_capped = lambda sid, cmd, timeout=15: (
        calls.append((sid, cmd)) or "uid=0(root) gid=0(root)")
    out = pe._direct_priv_check("3")
    assert calls == [("3", "id")], calls
    assert out.startswith("[command_shell id] uid=0(root)"), out


def test_bytes_session_type_decoded():
    pe.msf_session = _FakeMsf(b"meterpreter")
    pe._session_command_capped = lambda sid, cmd, timeout=15: "Server username: vagrant"
    out = pe._direct_priv_check("5")
    assert out.startswith("[meterpreter getuid]"), out


def test_unknown_type_defaults_to_id():
    class _Boom:
        def get_session_type(self, sid):
            raise RuntimeError("no lab")
    pe.msf_session = _Boom()
    pe._session_command_capped = lambda sid, cmd, timeout=15: "uid=1000(vagrant)"
    out = pe._direct_priv_check("3")
    assert "[command_shell id]" in out, out


def test_empty_first_read_retries():
    pe.msf_session = _FakeMsf("meterpreter")
    seq = iter(["(no output)", "Server username: root"])
    pe._session_command_capped = lambda sid, cmd, timeout=15: next(seq)
    out = pe._direct_priv_check("7")
    assert "Server username: root" in out, out


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
