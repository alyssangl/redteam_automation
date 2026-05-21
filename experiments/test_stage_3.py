"""
Offline correctness test for Stage 3 of the judge redesign.

Verifies:
  1. judge() returns expected actions for canned LLM responses
  2. judge() defaults to 'continue' on LLM error or unknown action
  3. _execute_node consults judge on retry and escalates early when told to
  4. _execute_node with use_judge=False preserves old behaviour (full retries)
  5. _try_replanner respects budget + explore flag
  6. run_graph's post-node judge can force replanner even on success

Run: python experiments/test_stage_3.py
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


def check(label: str, cond: bool, detail: str = ""):
    icon = PASS if cond else FAIL
    print(f"  {icon} {label}" + (f" -- {detail}" if detail else ""))
    results.append((label, cond))


def make_logger() -> tuple[logging.Logger, StringIO]:
    buf = StringIO()
    log = logging.getLogger(f"stage3_test_{id(buf)}")
    log.handlers.clear()
    log.setLevel(logging.DEBUG)
    h = logging.StreamHandler(buf)
    h.setLevel(logging.DEBUG)
    h.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    log.addHandler(h)
    log.propagate = False
    return log, buf


def llm_returning(payload: dict):
    """Stub call_llm that always returns a fixed JSON payload."""
    def _stub(messages, system_prompt=None, **kw):
        class R:
            content = json.dumps(payload)
        return R()
    return _stub


def llm_raising(exc: Exception):
    def _stub(messages, system_prompt=None, **kw):
        raise exc
    return _stub


def simple_graph(node_max_retries: int = 3) -> AttackGraph:
    g = AttackGraph.create(
        objective="test", target_ip="1.2.3.4", name="s3_test",
        attacker_ip="5.6.7.8",
    )
    n = AttackNode(
        id="n1", label="test node", agent_type="exploit",
        target_ip="1.2.3.4",
        commands_to_run=["echo hi"],
        tool_name="ssh",
        max_retries=node_max_retries,
    )
    g.add_node(n)
    return g


# -----------------------------------------------------------------------------
# Test 1 — judge() returns expected actions for canned responses
# -----------------------------------------------------------------------------

def test_judge_canned_responses():
    print("\n[Test 1] judge() maps canned LLM responses to expected actions")
    g = simple_graph()
    log, _ = make_logger()
    node = g.get_node("n1")

    cases = [
        ({"action": "continue", "hint": "looks fine"}, "continue"),
        ({"action": "adapt", "hint": "try alt path"}, "adapt"),
        ({"action": "escalate", "hint": "dead end"}, "escalate"),
    ]

    for payload, expected in cases:
        original = orch.call_llm
        orch.call_llm = llm_returning(payload)
        try:
            result = orch.judge("post_retry", node, g, log)
        finally:
            orch.call_llm = original
        check(f"  action={payload['action']!r} -> {expected}",
              result["action"] == expected,
              detail=f"got {result['action']!r}")


# -----------------------------------------------------------------------------
# Test 2 — judge() defaults to 'continue' on LLM error or unknown action
# -----------------------------------------------------------------------------

def test_judge_safe_defaults():
    print("\n[Test 2] judge() defaults to 'continue' on errors")
    g = simple_graph()
    log, _ = make_logger()
    node = g.get_node("n1")

    # LLM exception
    original = orch.call_llm
    orch.call_llm = llm_raising(RuntimeError("boom"))
    try:
        result = orch.judge("post_retry", node, g, log)
    finally:
        orch.call_llm = original
    check("LLM exception -> action='continue'", result["action"] == "continue")

    # Unknown action in response
    orch.call_llm = llm_returning({"action": "explode_universe", "hint": "x"})
    try:
        result = orch.judge("post_retry", node, g, log)
    finally:
        orch.call_llm = original
    check("Unknown action -> action='continue'", result["action"] == "continue")


# -----------------------------------------------------------------------------
# Test 3 — _execute_node respects post_retry judge=escalate
# -----------------------------------------------------------------------------

def test_execute_node_judge_escalates_early():
    print("\n[Test 3] _execute_node: judge='escalate' cuts retries short")
    g = simple_graph(node_max_retries=3)
    log, _ = make_logger()

    dispatch_calls = []
    def fake_dispatch(node, graph, log=None, explore=False):
        dispatch_calls.append(node.id)
        return {"success": False, "summary": "boom"}

    orig_dispatch = orch.dispatch_node
    orig_llm = orch.call_llm
    orch.dispatch_node = fake_dispatch
    orch.call_llm = llm_returning({"action": "escalate", "hint": "dead"})

    try:
        success, reason = orch._execute_node(
            "n1", g, log, explore=True,
            checkpoint_path="/tmp/_throwaway.json",
            use_judge=True,
        )
    finally:
        orch.dispatch_node = orig_dispatch
        orch.call_llm = orig_llm

    check("success=False", success is False)
    check("reason='judge_escalate'", reason == "judge_escalate",
          detail=f"got {reason!r}")
    check("dispatch called only once (judge cut retries short)",
          len(dispatch_calls) == 1, detail=f"got {len(dispatch_calls)} calls")


# -----------------------------------------------------------------------------
# Test 4 — use_judge=False preserves old behaviour (all retries used)
# -----------------------------------------------------------------------------

def test_execute_node_no_judge_runs_full_retries():
    print("\n[Test 4] _execute_node: use_judge=False runs full max_retries")
    g = simple_graph(node_max_retries=3)
    log, _ = make_logger()

    dispatch_calls = []
    def fake_dispatch(node, graph, log=None, explore=False):
        dispatch_calls.append(node.id)
        return {"success": False, "summary": "boom"}

    orig_dispatch = orch.dispatch_node
    orig_sleep = orch.time.sleep
    orch.dispatch_node = fake_dispatch
    orch.time.sleep = lambda s: None  # speed up the test

    try:
        success, reason = orch._execute_node(
            "n1", g, log, explore=True,
            checkpoint_path="/tmp/_throwaway.json",
            use_judge=False,
        )
    finally:
        orch.dispatch_node = orig_dispatch
        orch.time.sleep = orig_sleep

    check("success=False", success is False)
    check("reason='retries_exhausted'", reason == "retries_exhausted",
          detail=f"got {reason!r}")
    check("dispatch called 3 times (full max_retries)",
          len(dispatch_calls) == 3, detail=f"got {len(dispatch_calls)} calls")


# -----------------------------------------------------------------------------
# Test 5 — _try_replanner respects budget and explore flag
# -----------------------------------------------------------------------------

def test_try_replanner_budget_and_explore():
    print("\n[Test 5] _try_replanner: budget + explore flag")
    g = simple_graph()
    log, _ = make_logger()

    # explore=False -> no LLM call, returns (None, attempts unchanged)
    new_target, attempts = orch._try_replanner(
        g, "n1", log, "/tmp/x.json",
        replan_attempts=0, max_replan_attempts=5, explore=False,
    )
    check("explore=False -> (None, 0)", new_target is None and attempts == 0,
          detail=f"got ({new_target}, {attempts})")

    # budget exhausted -> no LLM call, attempts unchanged
    new_target, attempts = orch._try_replanner(
        g, "n1", log, "/tmp/x.json",
        replan_attempts=10, max_replan_attempts=10, explore=True,
    )
    check("budget exhausted -> (None, 10)",
          new_target is None and attempts == 10,
          detail=f"got ({new_target}, {attempts})")

    # explore=True, budget available -> LLM is called; we stub it to give_up
    orig_llm = orch.call_llm
    orch.call_llm = llm_returning({"action": "give_up", "reason": "test"})
    try:
        # Need a finished node for _replan_from to inspect
        g.get_node("n1").mark_success({"ports": [{"port": 22, "service": "ssh", "version": "x"}]}, "ok")
        new_target, attempts = orch._try_replanner(
            g, "n1", log, "/tmp/x.json",
            replan_attempts=0, max_replan_attempts=10, explore=True,
        )
    finally:
        orch.call_llm = orig_llm
    check("explore=True + give_up -> (None, attempts incremented)",
          new_target is None and attempts == 1,
          detail=f"got ({new_target}, {attempts})")


# -----------------------------------------------------------------------------
# Test 6 — judge_context shape (lightweight)
# -----------------------------------------------------------------------------

def test_judge_context_shape():
    print("\n[Test 6] _build_judge_context contains expected sections")
    g = simple_graph()
    node = g.get_node("n1")
    node.retries = 2
    node.metadata["last_failure_reason"] = "Permission denied on /root"
    node.add_command("echo x", tool="ssh", exit_code=0, output="x\n")

    ctx = orch._build_judge_context("post_retry", node, g)

    check("contains TRIGGER line", "TRIGGER: post_retry" in ctx)
    check("contains NODE id+label", "NODE: n1 (test node)" in ctx)
    check("contains RETRIES counter", "RETRIES: 2/3" in ctx)
    check("contains ALTERNATIVES_REMAINING",
          "ALTERNATIVES_REMAINING: 1" in ctx)
    check("contains last failure reason",
          "Permission denied on /root" in ctx)
    check("contains RECENT COMMAND OUTPUT section",
          "RECENT COMMAND OUTPUT" in ctx)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Stage 3 offline correctness check")
    print("=" * 70)

    test_judge_canned_responses()
    test_judge_safe_defaults()
    test_execute_node_judge_escalates_early()
    test_execute_node_no_judge_runs_full_retries()
    test_try_replanner_budget_and_explore()
    test_judge_context_shape()

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
