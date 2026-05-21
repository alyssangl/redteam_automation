"""
Offline correctness test for Stage 2 of the judge redesign.

Verifies that _replan_from now feeds prose context to the LLM:
  - raw_nmap_output is no longer stripped from findings
  - last 3 CommandRecord outputs (capped) are included
  - very long raw_nmap_output is capped at 8 KB

Run: python experiments/test_stage_2.py
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

from core_agents.attack_graph import AttackGraph, AttackNode, CommandRecord
import core_agents.orchestrator as orch


PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
results = []


def check(label: str, cond: bool, detail: str = ""):
    icon = PASS if cond else FAIL
    print(f"  {icon} {label}" + (f" -- {detail}" if detail else ""))
    results.append((label, cond))


def make_capturing_logger() -> tuple[logging.Logger, StringIO]:
    buf = StringIO()
    log = logging.getLogger(f"stage2_test_{id(buf)}")
    log.handlers.clear()
    log.setLevel(logging.DEBUG)
    h = logging.StreamHandler(buf)
    h.setLevel(logging.DEBUG)
    h.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    log.addHandler(h)
    log.propagate = False
    return log, buf


# -----------------------------------------------------------------------------
# Fixture: graph with a stuck node that has raw_nmap_output + 4 commands
# -----------------------------------------------------------------------------

def make_graph_with_loaded_node() -> AttackGraph:
    g = AttackGraph.create(
        objective="Get a shell",
        target_ip="192.168.34.7",
        name="stage2_test",
        attacker_ip="192.168.34.6",
    )
    node = AttackNode(
        id="recon",
        label="nmap",
        agent_type="recon",
        target_ip="192.168.34.7",
    )
    # Four commands — only the last 3 should land in the context.
    node.add_command(
        "nmap -sV 192.168.34.7",
        tool="ssh", exit_code=0,
        output="PORT 80/tcp open http  Apache 2.4.7\nFIRST_COMMAND_MARKER",
    )
    node.add_command(
        "msfconsole -q -x 'use auxiliary/scanner/ftp/ftp_version; run'",
        tool="msf_console", exit_code=0,
        output="ProFTPD 1.3.5 detected on port 21\nSECOND_COMMAND_MARKER",
    )
    node.add_command(
        "msfconsole -q -x 'use exploit/unix/ftp/proftpd_modcopy_exec; run'",
        tool="msf_console", exit_code=1,
        output="[-] Exploit failed: SITEPATH /var/www was not writable\nTHIRD_COMMAND_MARKER",
    )
    node.add_command(
        "curl -I http://192.168.34.7",
        tool="ssh", exit_code=0,
        output="HTTP/1.1 200 OK\nServer: Apache/2.4.7\nFOURTH_COMMAND_MARKER",
    )

    node.mark_success(
        findings={
            "success": True,
            "ports": [
                {"port": 21, "service": "ftp", "version": "ProFTPD 1.3.5"},
                {"port": 80, "service": "http", "version": "Apache 2.4.7"},
            ],
            "raw_nmap_output": (
                "Nmap scan report for 192.168.34.7\n"
                "PORT     STATE SERVICE VERSION\n"
                "21/tcp   open  ftp     ProFTPD 1.3.5\n"
                "80/tcp   open  http    Apache 2.4.7\n"
                "NMAP_OUTPUT_MARKER\n"
            ),
        },
        summary="Found ProFTPD 1.3.5 + Apache 2.4.7",
    )
    g.add_node(node)
    return g


# -----------------------------------------------------------------------------
# Helper: stub call_llm to capture the context string sent to the LLM
# -----------------------------------------------------------------------------

class _Capturer:
    """Stub for call_llm — records the context, returns a give_up response."""
    def __init__(self):
        self.captured = ""

    def __call__(self, messages, system_prompt=None, **kw):
        self.captured = messages[0].content

        class FakeResp:
            content = json.dumps({"action": "give_up", "reason": "test stub"})
        return FakeResp()


# -----------------------------------------------------------------------------
# Test 1 — raw_nmap_output preserved, last 3 commands included
# -----------------------------------------------------------------------------

def test_context_includes_raw_nmap_and_recent_commands():
    print("\n[Test 1] Replan context includes raw nmap + last 3 commands")
    graph = make_graph_with_loaded_node()
    log, _ = make_capturing_logger()
    cap = _Capturer()

    original = orch.call_llm
    orch.call_llm = cap
    try:
        orch._replan_from(graph, "recon", log)
    finally:
        orch.call_llm = original

    ctx = cap.captured

    check("context is non-empty", len(ctx) > 0,
          detail=f"len={len(ctx)}")
    check("raw_nmap_output preserved (NMAP_OUTPUT_MARKER present)",
          "NMAP_OUTPUT_MARKER" in ctx)
    check("RECENT COMMAND OUTPUT section present",
          "RECENT COMMAND OUTPUT" in ctx)
    check("FIRST command (4 ago) NOT in context",
          "FIRST_COMMAND_MARKER" not in ctx)
    check("SECOND command (3 ago) IS in context",
          "SECOND_COMMAND_MARKER" in ctx)
    check("THIRD command (2 ago) IS in context",
          "THIRD_COMMAND_MARKER" in ctx)
    check("FOURTH command (last) IS in context",
          "FOURTH_COMMAND_MARKER" in ctx)
    check("exit_code included for commands",
          '"exit_code": 1' in ctx)  # the failed proftpd one


# -----------------------------------------------------------------------------
# Test 2 — huge raw_nmap_output gets capped at 8 KB
# -----------------------------------------------------------------------------

def test_huge_nmap_output_capped():
    print("\n[Test 2] Very large raw_nmap_output is capped at 8 KB")
    graph = make_graph_with_loaded_node()
    # Replace nmap output with 50 KB of filler + tail marker
    recon = graph.nodes["recon"]
    recon.findings["raw_nmap_output"] = (
        ("X" * 50000) + "\nTAIL_MARKER_AT_END"
    )

    log, _ = make_capturing_logger()
    cap = _Capturer()

    original = orch.call_llm
    orch.call_llm = cap
    try:
        orch._replan_from(graph, "recon", log)
    finally:
        orch.call_llm = original

    ctx = cap.captured

    # The truncation prefix should appear once
    check("truncation prefix '...[truncated]...' present",
          "...[truncated]..." in ctx)
    check("tail of nmap output preserved (TAIL_MARKER_AT_END present)",
          "TAIL_MARKER_AT_END" in ctx)
    # The full 50 KB of X should NOT appear — context should be way smaller
    # than 50 KB total even including all the other fields.
    check("context total length far below 50 KB (i.e. cap worked)",
          len(ctx) < 30000, detail=f"len(ctx)={len(ctx)}")


# -----------------------------------------------------------------------------
# Test 3 — _recent_command_excerpts unit behaviour
# -----------------------------------------------------------------------------

def test_recent_command_excerpts_unit():
    print("\n[Test 3] _recent_command_excerpts unit behaviour")
    node = AttackNode(id="x", label="x")
    for i in range(5):
        node.add_command(f"cmd_{i}", tool="ssh", exit_code=i,
                         output=("Y" * 5000) + f"_TAIL_{i}")

    excerpts = orch._recent_command_excerpts(node, n=3, cap=1024)

    check("returns exactly 3 excerpts", len(excerpts) == 3,
          detail=f"got {len(excerpts)}")
    check("returns the LAST 3 (cmd_2, cmd_3, cmd_4)",
          [e["command"] for e in excerpts] == ["cmd_2", "cmd_3", "cmd_4"])
    check("each output_tail truncated near 1 KB",
          all(len(e["output_tail"]) <= 1100 for e in excerpts),
          detail=f"lens={[len(e['output_tail']) for e in excerpts]}")
    check("tails preserved (_TAIL_2/3/4 present)",
          all(f"_TAIL_{i}" in excerpts[idx]["output_tail"]
              for idx, i in enumerate([2, 3, 4])))


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Stage 2 offline correctness check")
    print("=" * 70)

    test_context_includes_raw_nmap_and_recent_commands()
    test_huge_nmap_output_capped()
    test_recent_command_excerpts_unit()

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
