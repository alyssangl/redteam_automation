"""
Offline correctness test for Stage 1 of the judge redesign.

Verifies that _replan_from no longer hard-rejects MSF module proposals
on a version mismatch — it logs an advisory warning and accepts the
proposal anyway.

Run: python experiments/test_stage_1.py
"""

from __future__ import annotations

import json
import logging
import sys
import types
from io import StringIO
from pathlib import Path

# Make project root importable when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ---- Prevent import-time MSF RPC connection ---------------------------------
# tools/metasploit_tools.py creates a real MetasploitSession at import time,
# which blocks when Kali isn't reachable. Register a fake before any orchestrator
# import triggers the real one.
_fake_msf = types.ModuleType("tools.metasploit_tools")

class _FakeMsfSession:
    def send_command(self, *a, **kw): return ""
    def run_session_command(self, *a, **kw): return ""

_fake_msf.msf_session = _FakeMsfSession()
_fake_msf.MetasploitSession = lambda *a, **kw: _FakeMsfSession()
_fake_msf.tool_session_command = lambda session_id, command: ""
sys.modules["tools.metasploit_tools"] = _fake_msf
# -----------------------------------------------------------------------------

from core_agents.attack_graph import (
    AttackGraph, AttackNode, NodeStatus,
)
import core_agents.orchestrator as orch


# -----------------------------------------------------------------------------
# Test fixtures
# -----------------------------------------------------------------------------

def make_graph_with_recon_done() -> AttackGraph:
    """Graph with one SUCCESS recon node. Target runs ProFTPD 1.3.5 (NOT 1.3.3c)."""
    g = AttackGraph.create(
        objective="Get a shell",
        target_ip="192.168.34.7",
        name="stage1_test",
        attacker_ip="192.168.34.6",
    )
    recon = AttackNode(
        id="recon",
        label="nmap",
        agent_type="recon",
        target_ip="192.168.34.7",
    )
    recon.mark_success(
        findings={
            "success": True,
            "ports": [
                {"port": 21, "service": "ftp", "version": "ProFTPD 1.3.5"},
                {"port": 22, "service": "ssh", "version": "OpenSSH 6.6.1p1"},
            ],
            "raw_nmap_output": "PORT 21/tcp ProFTPD 1.3.5",
        },
        summary="Found ProFTPD 1.3.5 on 21",
    )
    g.add_node(recon)
    return g


def make_stub_response(module: str) -> object:
    """Synthesize an LLM JSON response. Uses Stage 4's tiny-intent schema."""
    payload = {
        "action": "use_module",
        "target_hint": module,
        "label": f"Exploit via {module.rsplit('/', 1)[-1]}",
        "goal": "Get shell via ProFTPD",
        "rationale": "ProFTPD detected on 21",
    }

    class FakeResp:
        content = json.dumps(payload)

    return FakeResp()


def make_capturing_logger() -> tuple[logging.Logger, StringIO]:
    buf = StringIO()
    log = logging.getLogger("stage1_test")
    log.handlers.clear()
    log.setLevel(logging.DEBUG)
    h = logging.StreamHandler(buf)
    h.setLevel(logging.DEBUG)
    h.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    log.addHandler(h)
    log.propagate = False
    return log, buf


# -----------------------------------------------------------------------------
# Assertions helper
# -----------------------------------------------------------------------------

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
results = []


def check(label: str, cond: bool, detail: str = ""):
    icon = PASS if cond else FAIL
    print(f"  {icon} {label}" + (f" -- {detail}" if detail else ""))
    results.append((label, cond))


# -----------------------------------------------------------------------------
# Test 1 — mismatched module is ACCEPTED with advisory warning
# -----------------------------------------------------------------------------

def test_mismatch_is_advisory():
    print("\n[Test 1] proftpd_133c_backdoor proposed against ProFTPD 1.3.5 target")
    graph = make_graph_with_recon_done()
    log, buf = make_capturing_logger()

    # Patch call_llm in the orchestrator module
    original = orch.call_llm
    orch.call_llm = lambda messages, system_prompt=None, **kw: make_stub_response(
        "exploit/unix/ftp/proftpd_133c_backdoor"  # requires 1.3.3c — mismatch
    )

    try:
        result = orch._replan_from(graph, "recon", log)
    finally:
        orch.call_llm = original

    captured = buf.getvalue()

    check("returns a new node id (not None)", result is not None,
          detail=f"got {result!r}")
    check("new node was added to graph", result in graph.nodes)
    check("new edge recon -> new node exists",
          any(e.source == "recon" and e.target == result
              for e in graph.edges))

    # The persisted edge must NOT have hard version checks
    edge = next((e for e in graph.edges
                 if e.source == "recon" and e.target == result), None)
    edge_check_count = len(edge.checks) if edge else -1
    check("edge has no persisted hard version checks (checks==[])",
          edge is not None and len(edge.checks) == 0,
          detail=f"checks={edge_check_count}")

    check("log contains 'ADVISORY mismatch'",
          "ADVISORY mismatch" in captured)
    check("log does NOT contain 'REJECTED' for the proposal",
          "REJECTED proposal" not in captured)


# -----------------------------------------------------------------------------
# Test 2 — matched module still works (regression check)
# -----------------------------------------------------------------------------

def test_match_still_accepted():
    print("\n[Test 2] proftpd_modcopy_exec proposed against ProFTPD 1.3.5 target (matches)")
    graph = make_graph_with_recon_done()
    log, buf = make_capturing_logger()

    original = orch.call_llm
    orch.call_llm = lambda messages, system_prompt=None, **kw: make_stub_response(
        "exploit/unix/ftp/proftpd_modcopy_exec"  # requires 1.3.5 — match
    )

    try:
        result = orch._replan_from(graph, "recon", log)
    finally:
        orch.call_llm = original

    captured = buf.getvalue()

    check("returns a new node id", result is not None)
    check("log contains 'Module validation OK'",
          "Module validation OK" in captured)


# -----------------------------------------------------------------------------
# Test 3 — unknown module (not in MSF_MODULE_REQUIREMENTS) accepted silently
# -----------------------------------------------------------------------------

def test_unknown_module_accepted():
    print("\n[Test 3] Unknown module proposed -- should pass through")
    graph = make_graph_with_recon_done()
    log, buf = make_capturing_logger()

    original = orch.call_llm
    orch.call_llm = lambda messages, system_prompt=None, **kw: make_stub_response(
        "exploit/some/unknown/module"
    )

    try:
        result = orch._replan_from(graph, "recon", log)
    finally:
        orch.call_llm = original

    check("returns a new node id", result is not None)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Stage 1 offline correctness check")
    print("=" * 70)

    test_mismatch_is_advisory()
    test_match_still_accepted()
    test_unknown_module_accepted()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print()
    print("=" * 70)
    if passed == total:
        print(f"  ALL {total} CHECKS PASSED")
        sys.exit(0)
    else:
        print(f"  {passed}/{total} checks passed — {total - passed} FAILED")
        sys.exit(1)
