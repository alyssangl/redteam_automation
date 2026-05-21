"""
Offline test for Stage C — MSF failure cause tagging.

Verifies that _classify_msf_failure recognises each known MSF failure
pattern observed in Stage 1-4 + Fix 1 live logs, and that
_parse_msf_output stores the category + cause in findings, and that
_replan_from surfaces them in the REMAINING NODES FAILED entries.

Run: python experiments/test_stage_c_failure_causes.py
"""

from __future__ import annotations

import json
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
    log = logging.getLogger(f"sc_{id(object())}")
    log.handlers.clear()
    log.setLevel(logging.DEBUG)
    h = logging.StreamHandler(StringIO())
    h.setLevel(logging.DEBUG)
    log.addHandler(h)
    log.propagate = False
    return log


# -----------------------------------------------------------------------------
# Test 1 — each documented failure pattern from prior live logs
# -----------------------------------------------------------------------------

def test_classify_known_patterns():
    print("\n[Test 1] _classify_msf_failure recognises documented patterns")

    cases = [
        # Verbatim from prior live logs
        ("[-] Failed to load module: exploit/linux/samba/usermap_script",
         "module_load_failed"),
        ("[-] Exploit failed: cmd/unix/reverse_python is not a compatible payload.\n"
         "[*] Exploit completed, but no session was created.",
         "incompatible_payload"),
        ("[-] 192.168.34.7:21 - Exploit aborted due to failure: unknown: "
         "192.168.34.7:21 - Failure copying PHP payload to website path, "
         "directory not writable?\n[*] Exploit completed, but no session was created.",
         "writable_path_missing"),
        ("[*] Checking for cookie\n[!] Caution: Cookie not found, maybe you "
         "need to adjust TARGETURI\n[-] Exploit aborted due to failure: "
         "bad-config: No cookie found and no name given",
         "wrong_targeturi"),
        ("connect to 192.168.0.1 port 22: Connection refused",
         "network_refused"),
        ("[-] Exploit aborted due to failure: bad-config: missing key",
         "config_problem"),
        ("ssh: connect timed out",
         "timeout"),
    ]
    for output, expected_cat in cases:
        cat, phrase = orch._classify_msf_failure(output)
        check(f"  '{output[:50]}...' -> {expected_cat}",
              cat == expected_cat,
              detail=f"got {cat!r}")
        if cat == expected_cat:
            check(f"    cause phrase non-empty",
                  len(phrase) > 0)


# -----------------------------------------------------------------------------
# Test 2 — unrecognised failure falls through to 'generic'
# -----------------------------------------------------------------------------

def test_classify_generic_fallback():
    print("\n[Test 2] Unknown failure shape returns 'generic'")
    output = "[*] Some unrelated MSF output without our known phrases"
    cat, phrase = orch._classify_msf_failure(output)
    check("category == 'generic'", cat == "generic")
    check("phrase is empty for generic", phrase == "")


# -----------------------------------------------------------------------------
# Test 3 — _parse_msf_output stores failure_category + failure_cause
# -----------------------------------------------------------------------------

def test_parse_msf_stores_category():
    print("\n[Test 3] _parse_msf_output stores failure_category + failure_cause")
    log = make_logger()
    node = AttackNode(id="x", label="x", agent_type="exploit",
                      module="exploit/unix/ftp/proftpd_modcopy_exec")
    output = (
        "[*] Started reverse TCP handler on 192.168.34.6:4444\n"
        "[*] 192.168.34.7:21 - Connected to FTP server\n"
        "[-] 192.168.34.7:21 - Exploit aborted due to failure: unknown: "
        "Failure copying PHP payload to website path, directory not writable?\n"
        "[*] Exploit completed, but no session was created."
    )
    findings = orch._parse_msf_output(output, node, "192.168.34.7", log)
    check("success=False", findings.get("success") is False)
    check("failure_category == 'writable_path_missing'",
          findings.get("failure_category") == "writable_path_missing")
    check("failure_cause non-empty",
          len(findings.get("failure_cause", "")) > 0)
    check("failure_cause mentions 'directory not writable'",
          "directory not writable" in findings.get("failure_cause", "").lower())


# -----------------------------------------------------------------------------
# Test 4 — _replan_from surfaces failure_category in FAILED entries
# -----------------------------------------------------------------------------

def test_replan_context_surfaces_category():
    print("\n[Test 4] _replan_from context includes failure_category for FAILED nodes")
    g = AttackGraph.create(
        objective="x", target_ip="10.0.0.5", attacker_ip="10.0.0.1", name="sc",
    )
    recon = AttackNode(id="recon", label="recon", agent_type="recon")
    recon.mark_success(
        findings={"success": True,
                  "ports": [{"port": 21, "service": "ftp",
                             "version": "ProFTPD 1.3.5"}]},
        summary="recon",
    )
    g.add_node(recon)

    # Pre-seed a FAILED node with a known failure_category
    failed = AttackNode(
        id="proftpd", label="proftpd attempt", agent_type="exploit",
        module="exploit/unix/ftp/proftpd_modcopy_exec",
    )
    failed.status = NodeStatus.FAILED.value
    failed.findings = {
        "failure_category": "writable_path_missing",
        "failure_cause": "Failure copying PHP payload to website path, directory not writable?",
    }
    failed.metadata["last_failure_reason"] = "Exploit completed but no session created"
    g.add_node(failed)

    captured = {"context": ""}
    def stub(messages, system_prompt=None, **kw):
        captured["context"] = messages[0].content
        class R:
            content = json.dumps({"action": "give_up", "reason": "test"})
        return R()

    log = make_logger()
    orig = orch.call_llm
    orch.call_llm = stub
    try:
        orch._replan_from(g, "recon", log)
    finally:
        orch.call_llm = orig

    ctx = captured["context"]
    check("context contains 'failure_category'", '"failure_category"' in ctx)
    check("context contains the writable_path_missing tag",
          '"writable_path_missing"' in ctx)
    check("context contains failure_cause snippet",
          "directory not writable" in ctx.lower())


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Stage C offline check -- MSF failure cause tagging")
    print("=" * 70)

    test_classify_known_patterns()
    test_classify_generic_fallback()
    test_parse_msf_stores_category()
    test_replan_context_surfaces_category()

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
