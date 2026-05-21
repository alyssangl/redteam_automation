"""
Offline test for Stage B — session privilege extraction.

Verifies that _extract_privilege_from_msf_output parses uid/gid/groups
out of MSF output and that _parse_msf_output stores it in findings,
and that the judge/replanner contexts surface it.

Run: python experiments/test_stage_b_privilege.py
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

from core_agents.attack_graph import AttackGraph, AttackNode, NodeStatus
import core_agents.orchestrator as orch


PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
results = []


def check(label, cond, detail=""):
    icon = PASS if cond else FAIL
    print(f"  {icon} {label}" + (f" -- {detail}" if detail else ""))
    results.append((label, cond))


def make_logger():
    log = logging.getLogger("sb")
    log.handlers.clear()
    log.setLevel(logging.DEBUG)
    h = logging.StreamHandler(StringIO())
    h.setLevel(logging.DEBUG)
    log.addHandler(h)
    log.propagate = False
    return log


# -----------------------------------------------------------------------------
# Test 1 — _extract_privilege_from_msf_output: real vagrant brute-force output
# -----------------------------------------------------------------------------

def test_extract_vagrant_with_sudo():
    print("\n[Test 1] vagrant brute-force output (groups include sudo)")
    # Verbatim from Stage 1+ live logs
    output = (
        "Success: 'vagrant:vagrant' 'uid=900(vagrant) gid=900(vagrant) "
        "groups=900(vagrant),27(sudo) Linux ubuntu 3.13.0-24-generic ...'"
    )
    priv = orch._extract_privilege_from_msf_output(output)
    check("uid=900", priv.get("uid") == 900)
    check("user='vagrant'", priv.get("user") == "vagrant")
    check("gid=900", priv.get("gid") == 900)
    check("groups=['vagrant','sudo']", priv.get("groups") == ["vagrant", "sudo"])
    check("in_sudo_group=True (sudo in groups)", priv.get("in_sudo_group") is True)
    check("is_root=False (uid 900)", priv.get("is_root") is False)
    check("_derive_access_level == 'user_with_sudo'",
          orch._derive_access_level(priv) == "user_with_sudo")


# -----------------------------------------------------------------------------
# Test 2 — root output -> is_root, access_level=root
# -----------------------------------------------------------------------------

def test_extract_root():
    print("\n[Test 2] root user output")
    output = "uid=0(root) gid=0(root) groups=0(root)"
    priv = orch._extract_privilege_from_msf_output(output)
    check("uid=0", priv.get("uid") == 0)
    check("is_root=True", priv.get("is_root") is True)
    check("access_level == 'root'",
          orch._derive_access_level(priv) == "root")


# -----------------------------------------------------------------------------
# Test 3 — unprivileged user, no sudo group
# -----------------------------------------------------------------------------

def test_extract_normal_user():
    print("\n[Test 3] unprivileged user (no sudo group)")
    output = "uid=1000(alice) gid=1000(alice) groups=1000(alice),100(users)"
    priv = orch._extract_privilege_from_msf_output(output)
    check("uid=1000", priv.get("uid") == 1000)
    check("in_sudo_group=False", priv.get("in_sudo_group") is False)
    check("access_level == 'user'",
          orch._derive_access_level(priv) == "user")


# -----------------------------------------------------------------------------
# Test 4 — no id-style output -> empty dict, level=unknown
# -----------------------------------------------------------------------------

def test_extract_nothing():
    print("\n[Test 4] no uid= pattern -> empty dict")
    output = "Meterpreter session 1 opened (192.168.1.1:4444 -> 192.168.1.2:34567)"
    priv = orch._extract_privilege_from_msf_output(output)
    check("returns empty dict", priv == {})
    check("access_level on empty -> 'unknown'",
          orch._derive_access_level(priv) == "unknown")


# -----------------------------------------------------------------------------
# Test 5 — wheel/admin groups also flag in_sudo_group
# -----------------------------------------------------------------------------

def test_extract_wheel_group():
    print("\n[Test 5] wheel group (BSD/RHEL admin) also flags sudo")
    output = "uid=500(bob) gid=500(bob) groups=500(bob),10(wheel)"
    priv = orch._extract_privilege_from_msf_output(output)
    check("in_sudo_group=True (wheel detected)",
          priv.get("in_sudo_group") is True)


# -----------------------------------------------------------------------------
# Test 6 — _parse_msf_output stores priv info on session opened
# -----------------------------------------------------------------------------

def test_parse_msf_stores_privilege():
    print("\n[Test 6] _parse_msf_output stores session_user_info + access_level")
    log = make_logger()
    node = AttackNode(id="x", label="x", agent_type="exploit",
                      module="auxiliary/scanner/ssh/ssh_login")
    output = (
        "[*] 192.168.1.5:22 - Starting bruteforce\n"
        "[+] 192.168.1.5:22 - Success: 'vagrant:vagrant' "
        "'uid=900(vagrant) gid=900(vagrant) "
        "groups=900(vagrant),27(sudo) Linux ubuntu ...'\n"
        "[*] SSH session 5 opened\n"
    )
    findings = orch._parse_msf_output(output, node, "192.168.1.5", log)
    check("findings.success=True", findings.get("success") is True)
    check("findings has session_user_info",
          "session_user_info" in findings)
    check("access_level == 'user_with_sudo'",
          findings.get("access_level") == "user_with_sudo")


# -----------------------------------------------------------------------------
# Test 7 — _format_session_privilege_line surfaces it
# -----------------------------------------------------------------------------

def test_privilege_line_in_context():
    print("\n[Test 7] _format_session_privilege_line returns a useful one-liner")
    g = AttackGraph.create(
        objective="x", target_ip="1.2.3.4", attacker_ip="5.6.7.8", name="t",
    )
    n = AttackNode(id="ssh", label="ssh", agent_type="exploit")
    n.mark_success(
        findings={
            "success": True, "session_id": "5",
            "session_user_info": {
                "uid": 900, "user": "vagrant",
                "groups": ["vagrant", "sudo"],
                "in_sudo_group": True, "is_root": False,
            },
            "access_level": "user_with_sudo",
        },
        summary="opened",
    )
    g.add_node(n)

    line = orch._format_session_privilege_line(g)
    check("line non-empty", len(line) > 0)
    check("includes user name", "vagrant" in line)
    check("includes uid", "uid=900" in line)
    check("includes can_sudo=True", "can_sudo=True" in line)
    check("includes access_level", "user_with_sudo" in line)


# -----------------------------------------------------------------------------
# Test 8 — judge context includes privilege when session is open
# -----------------------------------------------------------------------------

def test_judge_context_has_privilege():
    print("\n[Test 8] _build_judge_context surfaces privilege")
    g = AttackGraph.create(
        objective="x", target_ip="1.2.3.4", attacker_ip="5.6.7.8", name="t",
    )
    ssh = AttackNode(id="ssh", label="ssh", agent_type="exploit")
    ssh.mark_success(
        findings={
            "success": True,
            "session_user_info": {"uid": 900, "user": "vagrant",
                                  "groups": ["vagrant", "sudo"],
                                  "in_sudo_group": True, "is_root": False},
            "access_level": "user_with_sudo",
        },
        summary="opened",
    )
    g.add_node(ssh)
    other = AttackNode(id="other", label="other", agent_type="impact")
    g.add_node(other)

    ctx = orch._build_judge_context("post_retry", other, g)
    check("judge context contains 'SESSION PRIVILEGE:'",
          "SESSION PRIVILEGE:" in ctx)
    check("contains user 'vagrant'", "vagrant" in ctx)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Stage B offline check -- session privilege extraction")
    print("=" * 70)

    test_extract_vagrant_with_sudo()
    test_extract_root()
    test_extract_normal_user()
    test_extract_nothing()
    test_extract_wheel_group()
    test_parse_msf_stores_privilege()
    test_privilege_line_in_context()
    test_judge_context_has_privilege()

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
