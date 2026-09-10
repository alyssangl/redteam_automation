"""Offline tests — impact upgrades a read-zombie command_shell to meterpreter.

The UnrealIRCd cmd/unix/reverse_perl command_shell on MS3 read-zombies: writes land
but every read returns nothing (confirmed via both run_session_command and the raw
session.shell_read API, on a fresh target). shell_to_meterpreter is write-driven, so
it upgrades even a read-zombie into a meterpreter with reliable I/O — which is how
persistence grounds on the same shell. impact._find_live_impact_session now does the
same. These tests stub the upgrade (no lab) and pin the three paths.

Run:
    python tests/test_impact_meterpreter_upgrade.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.impact as impact
import stages.persistence as persistence


def test_command_shell_upgraded_to_meterpreter():
    orig = persistence._upgrade_shell_to_meterpreter
    try:
        persistence._upgrade_shell_to_meterpreter = lambda target, sid, **k: "5"
        s, t, status = impact._find_live_impact_session("192.168.34.7", "2", "command_shell")
        assert s == "5" and t == "meterpreter", (s, t)
        assert "upgraded" in status
    finally:
        persistence._upgrade_shell_to_meterpreter = orig


def test_existing_meterpreter_kept_without_upgrade():
    orig = persistence._upgrade_shell_to_meterpreter
    called = []
    try:
        persistence._upgrade_shell_to_meterpreter = lambda *a, **k: (called.append(1) or "9")
        s, t, status = impact._find_live_impact_session("192.168.34.7", "3", "meterpreter")
        assert s == "3" and t == "meterpreter" and status == "alive"
        assert not called, "must not upgrade a session that is already meterpreter"
    finally:
        persistence._upgrade_shell_to_meterpreter = orig


def test_upgrade_failure_falls_back_to_responsive_shell():
    orig_up = persistence._upgrade_shell_to_meterpreter
    orig_resp = impact._shell_responds
    try:
        persistence._upgrade_shell_to_meterpreter = lambda *a, **k: None   # upgrade fails
        impact._shell_responds = lambda sid, **k: True                      # raw shell answers
        s, t, status = impact._find_live_impact_session("192.168.34.7", "2", "command_shell")
        assert s == "2" and status == "alive"
    finally:
        persistence._upgrade_shell_to_meterpreter = orig_up
        impact._shell_responds = orig_resp


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
