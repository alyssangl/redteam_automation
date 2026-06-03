"""Offline tests for v16b — privesc session propagation.

Covers the pure logic that lets a privesc kernel-path / upgrade session reach the
impact stage instead of being orphaned:

  - _scan_opened_sessions: parse 'X session N opened' lines, newest first.
  - _resolve_final_session: prefer the newest live opened session, else the
    original session in state.
  - orchestrator._find_session: prefer the most-escalated successful session.

No lab needed (lazy MSF). Run: python tests/test_privesc_session_propagation.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_core.messages import HumanMessage, AIMessage, ToolMessage

import stages.privesc as pe
from core_agents.orchestrator import _find_session


# --- _scan_opened_sessions ---------------------------------------------------

def test_scan_picks_meterpreter_and_typing():
    msgs = [ToolMessage(content="[*] Meterpreter session 7 opened (1.2.3.4)", tool_call_id="a")]
    assert pe._scan_opened_sessions(msgs) == [("7", "meterpreter")]


def test_scan_command_shell_typing():
    msgs = [ToolMessage(content="[*] Command shell session 3 opened", tool_call_id="a")]
    assert pe._scan_opened_sessions(msgs) == [("3", "command_shell")]


def test_scan_newest_first():
    msgs = [
        ToolMessage(content="Meterpreter session 5 opened", tool_call_id="a"),
        ToolMessage(content="Meterpreter session 9 opened", tool_call_id="b"),
    ]
    # newest (last in history) comes first
    assert pe._scan_opened_sessions(msgs)[0] == ("9", "meterpreter")


def test_scan_ignores_prose_and_init():
    # The original session id appears only as prose in the init HumanMessage,
    # never as an 'opened' line -> must NOT be matched.
    msgs = [HumanMessage(content="Session: command_shell (ID: 4)\nObjective: root")]
    assert pe._scan_opened_sessions(msgs) == []


# --- _resolve_final_session --------------------------------------------------

def test_resolve_prefers_opened_when_live(monkeypatch=None):
    pe._live_session_ids = lambda: {"7"}
    state = {
        "messages": [ToolMessage(content="Meterpreter session 7 opened", tool_call_id="a")],
        "session_id": "4", "session_type": "command_shell",
    }
    assert pe._resolve_final_session(state) == ("7", "meterpreter")


def test_resolve_skips_dead_opened_falls_back_to_state():
    # session 7 was opened but is no longer in session.list -> use the original.
    pe._live_session_ids = lambda: {"4"}
    state = {
        "messages": [ToolMessage(content="Meterpreter session 7 opened", tool_call_id="a")],
        "session_id": "4", "session_type": "command_shell",
    }
    assert pe._resolve_final_session(state) == ("4", "command_shell")


def test_resolve_no_upgrade_returns_original():
    pe._live_session_ids = lambda: {"4"}
    state = {"messages": [HumanMessage(content="no sessions here")],
             "session_id": "4", "session_type": "command_shell"}
    assert pe._resolve_final_session(state) == ("4", "command_shell")


def test_resolve_live_unavailable_trusts_opened():
    # session.list down (None) -> trust the opened session rather than discard it.
    pe._live_session_ids = lambda: None
    state = {"messages": [ToolMessage(content="Meterpreter session 8 opened", tool_call_id="a")],
             "session_id": "4", "session_type": "command_shell"}
    assert pe._resolve_final_session(state) == ("8", "meterpreter")


# --- orchestrator._find_session ----------------------------------------------

def test_find_session_single_predecessor_unchanged():
    preceding = {"exploit": {"success": True, "session_id": "1",
                             "session_type": "command_shell", "access_level": "user"}}
    assert _find_session(preceding) == ("1", "command_shell", "user")


def test_find_session_prefers_escalated_root():
    preceding = {
        "exploit": {"success": True, "session_id": "1",
                    "session_type": "command_shell", "access_level": "user"},
        "privesc": {"success": True, "session_id": "7",
                    "session_type": "meterpreter", "new_level": "root"},
    }
    assert _find_session(preceding) == ("7", "meterpreter", "root")


def test_find_session_failed_privesc_ignored():
    preceding = {
        "exploit": {"success": True, "session_id": "1",
                    "session_type": "command_shell", "access_level": "user"},
        "privesc": {"success": False, "session_id": "7",
                    "session_type": "meterpreter", "new_level": "user"},
    }
    assert _find_session(preceding) == ("1", "command_shell", "user")


def test_find_session_none_returns_empty():
    assert _find_session({"recon": {"success": True, "ports": [22]}}) == ("", "", "unknown")
    assert _find_session({"x": {"success": False, "session_id": "9"}}) == ("", "", "unknown")


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
