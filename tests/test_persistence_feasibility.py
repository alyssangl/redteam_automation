"""Offline tests — technique feasibility precheck (V1 fix).

A locked technique that cannot work here (systemd absent, or root-only on a
non-root session) must fail FAST to technique_infeasible so the replanner grows a
compatible technique — instead of grinding the full retry budget. Probes are
best-effort: an ambiguous/failed probe must NOT block a workable technique.

No lab (session probe mocked). Run:
    python tests/test_persistence_feasibility.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.persistence as ps
from core_agents import mitre


class _FakeMsf:
    def __init__(self, responses):  # responses: dict substr->output, or callable
        self.responses = responses
        self.calls = []

    def run_session_command(self, sid, cmd, timeout=15):
        self.calls.append(cmd)
        if callable(self.responses):
            return self.responses(cmd)
        for needle, out in self.responses.items():
            if needle in cmd:
                return out
        return ""


def _tech(slug):
    return mitre.get_technique("persistence", slug)


def test_systemd_absent_is_infeasible():
    ps.msf_session = _FakeMsf({"systemctl": "NO_SYSTEMCTL\n", "id": "uid=0(root)"})
    ok, reason = ps._technique_feasibility_precheck(
        _tech("systemd_service"), "1", "command_shell", "root")
    assert ok is False and "systemd" in reason.lower(), (ok, reason)


def test_systemd_present_is_feasible():
    ps.msf_session = _FakeMsf({"systemctl": "/bin/systemctl\n", "id": "uid=0(root)"})
    ok, _ = ps._technique_feasibility_precheck(
        _tech("systemd_service"), "1", "command_shell", "root")
    assert ok is True


def test_root_only_technique_blocked_on_nonroot_session():
    # user_account is root-only; a non-root session must block it
    ps.msf_session = _FakeMsf({"id": "uid=1001(boba_fett) gid=1001"})
    ok, reason = ps._technique_feasibility_precheck(
        _tech("user_account"), "1", "command_shell", "unknown")
    assert ok is False and "root" in reason.lower(), (ok, reason)


def test_root_only_technique_allowed_on_root_session():
    ps.msf_session = _FakeMsf({"id": "uid=0(root) gid=0(root)"})
    ok, _ = ps._technique_feasibility_precheck(
        _tech("user_account"), "1", "command_shell", "unknown")
    assert ok is True


def test_ambiguous_probe_does_not_block():
    # probe returns nothing usable -> must NOT block (feasible by default)
    ps.msf_session = _FakeMsf({})
    ok, _ = ps._technique_feasibility_precheck(
        _tech("user_account"), "1", "command_shell", "unknown")
    assert ok is True


def test_probe_exception_does_not_block():
    class _Boom:
        def run_session_command(self, *a, **k): raise RuntimeError("no lab")
    ps.msf_session = _Boom()
    ok, _ = ps._technique_feasibility_precheck(
        _tech("systemd_service"), "1", "command_shell", "unknown")
    assert ok is True


def test_user_level_technique_never_blocked():
    # cron is user-level -> feasibility precheck returns feasible regardless of priv
    ps.msf_session = _FakeMsf({"id": "uid=1001(boba_fett)"})
    ok, _ = ps._technique_feasibility_precheck(
        _tech("cron_job"), "1", "command_shell", "user")
    assert ok is True


def test_meterpreter_uses_getuid_not_id():
    fake = _FakeMsf({"getuid": "Server username: boba_fett"})
    ps.msf_session = fake
    ps._probe_priv("1", "meterpreter")
    assert any("getuid" in c for c in fake.calls) and not any(c == "id" for c in fake.calls)


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
