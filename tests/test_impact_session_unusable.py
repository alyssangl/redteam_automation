"""Offline tests — impact surfaces failure_category=session_unusable on a read-zombie.

A privesc docker/chroot breakout can read-zombie the fragile UnrealIRCd command_shell:
still listed in session.list, but every shell READ returns nothing, so a proof file
can never be written-and-verified. Impact must (a) substitute a live, responsive
session if one exists, and (b) otherwise abort with failure_category=session_unusable
so the orchestrator's session_unusable -> re-exploit steer fires (instead of the node
dying 'generic' and the walker non-terminating on the final file_drop).

The MSF RPC is faked (no lab, no OpenAI). Run:
    python tests/test_impact_session_unusable.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.impact as impact
import stages.persistence as persistence

_NONCE = impact._ALIVE_PROBE_NONCE


class FakeMsf:
    """Minimal stand-in for tools.metasploit_tools.msf_session.

    `responsive_ids` echo back an `echo <nonce>` (a live shell); everything else
    returns "(no output)" (a read-zombie). `sessions` is what session.list returns.
    """
    def __init__(self, responsive_ids=(), sessions=None):
        self.responsive_ids = {str(s) for s in responsive_ids}
        self._sessions = sessions if sessions is not None else {}
        self.client = self  # so msf_session.client.call(...) resolves

    def run_session_command(self, session_id, command, timeout=None):
        if str(session_id) in self.responsive_ids and command.startswith("echo "):
            return command[len("echo "):]           # a live shell echoes back
        return "(no output)"                          # read-zombie / dead

    def call(self, method, *args):
        if method == "session.list":
            return self._sessions
        return {}


def _install(fake):
    impact.msf_session = fake
    # HERMETIC: the command_shell path in _find_live_impact_session upgrades to
    # meterpreter FIRST via persistence._upgrade_shell_to_meterpreter, which uses
    # persistence's own (un-faked) msf_session and would reach the LIVE lab — passing
    # only when the lab is DOWN (upgrade times out → fallback). Stub it to None so the
    # probe/substitute/abort logic under test runs deterministically regardless of lab
    # state. The upgrade path itself is covered by test_impact_meterpreter_upgrade.py.
    persistence._upgrade_shell_to_meterpreter = lambda *a, **k: None


def _target_shell(host="192.168.34.7", stype=b"shell"):
    return {b"session_host": host.encode(), b"type": stype}


# --- _shell_responds -------------------------------------------------------

def test_shell_responds_true_when_echoed():
    _install(FakeMsf(responsive_ids=["3"]))
    assert impact._shell_responds("3") is True


def test_shell_responds_false_on_zombie():
    _install(FakeMsf(responsive_ids=[]))     # every read returns "(no output)"
    assert impact._shell_responds("1") is False


# --- _find_live_impact_session --------------------------------------------

def test_probe_keeps_responsive_session():
    _install(FakeMsf(responsive_ids=["1"], sessions={1: _target_shell()}))
    sid, stype, status = impact._find_live_impact_session("192.168.34.7", "1", "command_shell")
    assert sid == "1" and stype == "command_shell" and status == "alive"


def test_probe_trusts_meterpreter_without_echo():
    # meterpreter has reliable framed I/O — it is not echo-probed.
    _install(FakeMsf(responsive_ids=[]))
    sid, stype, status = impact._find_live_impact_session("192.168.34.7", "7", "meterpreter")
    assert sid == "7" and stype == "meterpreter" and status == "alive"


def test_probe_substitutes_live_session_for_zombie():
    # session 1 is a read-zombie; session 2 (same target) responds -> substitute it.
    _install(FakeMsf(
        responsive_ids=["2"],
        sessions={1: _target_shell(), 2: _target_shell()},
    ))
    sid, stype, status = impact._find_live_impact_session("192.168.34.7", "1", "command_shell")
    assert sid == "2" and stype == "command_shell" and status.startswith("substituted")


def test_probe_none_when_zombie_and_no_substitute():
    # session 1 zombie, no other live session -> unusable.
    _install(FakeMsf(responsive_ids=[], sessions={1: _target_shell()}))
    sid, stype, status = impact._find_live_impact_session("192.168.34.7", "1", "command_shell")
    assert sid is None and stype is None
    assert "read-zombie" in status


def test_probe_skips_another_zombie_candidate():
    # both sessions are read-zombies -> don't swap one corpse for another.
    _install(FakeMsf(responsive_ids=[], sessions={1: _target_shell(), 2: _target_shell()}))
    sid, _, _ = impact._find_live_impact_session("192.168.34.7", "1", "command_shell")
    assert sid is None


def test_probe_ignores_other_target_sessions():
    # a live session on a DIFFERENT host must not be substituted in.
    _install(FakeMsf(
        responsive_ids=["2"],
        sessions={1: _target_shell(), 2: _target_shell(host="10.9.9.9")},
    ))
    sid, _, _ = impact._find_live_impact_session("192.168.34.7", "1", "command_shell")
    assert sid is None


# --- run_impact end-to-end categorization (no graph/LLM reached) -----------

def test_run_impact_returns_session_unusable_on_persistent_zombie():
    _install(FakeMsf(responsive_ids=[], sessions={1: _target_shell()}))
    findings = impact.run_impact(
        target_ip="192.168.34.7",
        objective="Write /tmp/pwned.txt and read it back",
        session_id="1",
        session_type="command_shell",
        access_level="root",
    )
    assert findings.get("success") is False
    assert findings.get("failure_category") == "session_unusable", \
        f"impact must categorize a persistent read-zombie as session_unusable, got {findings!r}"


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
