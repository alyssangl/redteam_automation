"""
Offline correctness test for Stage 4 of the judge redesign.

Verifies:
  1. _guess_rport_from_module returns expected ports for known services
  2. _expand_intent_to_node fills RHOSTS/LHOST/LPORT defaults for use_module
  3. _expand_intent_to_node picks tool_name=session when a session exists,
     ssh when none does, for run_commands
  4. _expand_intent_to_node generates unique node ids on collision
  5. _expand_intent_to_node returns None for malformed/empty intents
  6. _replan_from end-to-end with a tiny use_module intent produces a
     full node with all defaults populated
  7. _replan_from end-to-end with a tiny run_commands intent produces a
     full node with commands split correctly

Run: python experiments/test_stage_4.py
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


def make_logger():
    buf = StringIO()
    log = logging.getLogger(f"stage4_{id(buf)}")
    log.handlers.clear()
    log.setLevel(logging.DEBUG)
    h = logging.StreamHandler(buf)
    h.setLevel(logging.DEBUG)
    log.addHandler(h)
    log.propagate = False
    return log, buf


def llm_returning(payload: dict):
    def _stub(messages, system_prompt=None, **kw):
        class R:
            content = json.dumps(payload)
        return R()
    return _stub


def graph_with_session() -> AttackGraph:
    """Graph where one node has succeeded with an active session."""
    g = AttackGraph.create(
        objective="test", target_ip="10.0.0.5", attacker_ip="10.0.0.1",
        name="s4_test",
    )
    n = AttackNode(id="ssh_open", label="SSH bruteforce", agent_type="exploit")
    n.mark_success(
        findings={"success": True, "session_id": "7", "session_type": "command_shell",
                  "ports": [{"port": 21, "service": "ftp", "version": "ProFTPD 1.3.5"}]},
        summary="ssh open",
    )
    g.add_node(n)
    return g


def graph_no_session() -> AttackGraph:
    g = AttackGraph.create(
        objective="test", target_ip="10.0.0.5", attacker_ip="10.0.0.1",
        name="s4_test_ns",
    )
    n = AttackNode(id="recon", label="Recon", agent_type="recon")
    n.mark_success(
        findings={"success": True,
                  "ports": [{"port": 21, "service": "ftp", "version": "ProFTPD 1.3.5"}]},
        summary="recon",
    )
    g.add_node(n)
    return g


# -----------------------------------------------------------------------------
# Test 1 — _guess_rport_from_module
# -----------------------------------------------------------------------------

def test_guess_rport():
    print("\n[Test 1] _guess_rport_from_module")
    cases = [
        ("exploit/multi/ssh/sshexec", 22),
        ("exploit/unix/ftp/proftpd_modcopy_exec", 21),
        ("exploit/multi/samba/usermap_script", 445),
        ("exploit/multi/http/drupal_drupageddon", 80),
        ("exploit/multi/http/rails_secret_deserialization", 80),
        ("exploit/windows/mysql/mysql_yassl_hello", 3306),
        ("exploit/unix/irc/unreal_ircd_3281_backdoor", 6667),
        ("exploit/multi/foo/totally_unknown_module", None),
    ]
    for mod, expected in cases:
        got = orch._guess_rport_from_module(mod)
        check(f"  {mod.split('/')[-1]} -> {expected}", got == expected,
              detail=f"got {got}")


# -----------------------------------------------------------------------------
# Test 2 — use_module expansion fills RHOSTS/LHOST/LPORT/RPORT
# -----------------------------------------------------------------------------

def test_expand_use_module_fills_defaults():
    print("\n[Test 2] _expand_intent_to_node: use_module defaults")
    g = graph_no_session()
    intent = {
        "action": "use_module",
        "target_hint": "exploit/unix/ftp/proftpd_modcopy_exec",
        "label": "ProFTPD modcopy",
        "goal": "Get shell via FTP",
    }
    node = orch._expand_intent_to_node(intent, g, g.get_node("recon"))
    check("returns an AttackNode", node is not None)
    check("agent_type=exploit", node.agent_type == "exploit")
    check("tool_name=metasploit", node.tool_name == "metasploit")
    check("module set", node.module == "exploit/unix/ftp/proftpd_modcopy_exec")
    check("target_ip=graph.target_ip",
          node.target_ip == g.target_ip)
    check("module_options.RHOSTS=graph.target_ip",
          node.module_options.get("RHOSTS") == g.target_ip)
    check("module_options.RPORT=21 (guessed from proftpd)",
          node.module_options.get("RPORT") == 21)
    check("payload_options.LHOST=graph.attacker_ip",
          node.payload_options.get("LHOST") == g.attacker_ip)
    check("payload_options.LPORT=4444 (default)",
          node.payload_options.get("LPORT") == 4444)
    check("has 'intent_expanded' tag", "intent_expanded" in node.tags)


# -----------------------------------------------------------------------------
# Test 3 — run_commands with/without session picks correct tool
# -----------------------------------------------------------------------------

def test_expand_run_commands_picks_tool():
    print("\n[Test 3] _expand_intent_to_node: run_commands tool selection")

    # With session
    g_ses = graph_with_session()
    intent_ses = {
        "action": "run_commands",
        "target_hint": "id\ncat /etc/passwd",
        "label": "passwd dump",
    }
    n = orch._expand_intent_to_node(intent_ses, g_ses, g_ses.get_node("ssh_open"))
    check("with session: tool_name=session", n.tool_name == "session")
    check("with session: agent_type=impact", n.agent_type == "impact")
    check("commands split on newline", n.commands_to_run == ["id", "cat /etc/passwd"])

    # Without session
    g_ns = graph_no_session()
    intent_ns = {
        "action": "run_commands",
        "target_hint": "nmap -sV 10.0.0.5",
    }
    n2 = orch._expand_intent_to_node(intent_ns, g_ns, g_ns.get_node("recon"))
    check("no session: tool_name=ssh", n2.tool_name == "ssh")
    check("no session: agent_type=discovery", n2.agent_type == "discovery")


# -----------------------------------------------------------------------------
# Test 4 — id collision handling
# -----------------------------------------------------------------------------

def test_id_collision():
    print("\n[Test 4] id collision yields a unique id")
    g = graph_no_session()
    intent = {
        "action": "use_module",
        "target_hint": "exploit/unix/ftp/proftpd_modcopy_exec",
    }
    n1 = orch._expand_intent_to_node(intent, g, g.get_node("recon"))
    g.add_node(n1)
    n2 = orch._expand_intent_to_node(intent, g, g.get_node("recon"))
    check("first id chosen", n1.id == "proftpd_modcopy_exec")
    check("second id is incremented", n2.id == "proftpd_modcopy_exec_2",
          detail=f"got {n2.id!r}")


# -----------------------------------------------------------------------------
# Test 5 — malformed intents
# -----------------------------------------------------------------------------

def test_malformed_intents():
    print("\n[Test 5] malformed intents return None")
    g = graph_no_session()
    cases = [
        {"action": "use_module"},                              # no target_hint
        {"action": "use_module", "target_hint": ""},           # empty target_hint
        {"action": "use_module", "target_hint": "   "},        # whitespace
        {"action": "totally_made_up", "target_hint": "x"},     # unknown action
        {"action": "run_commands", "target_hint": "\n\n  \n"}, # commands but all blank
    ]
    for c in cases:
        n = orch._expand_intent_to_node(c, g, g.get_node("recon"))
        check(f"  {json.dumps(c)[:60]} -> None", n is None,
              detail=f"got {type(n).__name__}")


# -----------------------------------------------------------------------------
# Test 6 — _replan_from with use_module intent end-to-end
# -----------------------------------------------------------------------------

def test_replan_use_module_e2e():
    print("\n[Test 6] _replan_from end-to-end with use_module intent")
    g = graph_no_session()
    log, _ = make_logger()
    orig = orch.call_llm
    orch.call_llm = llm_returning({
        "action": "use_module",
        "target_hint": "exploit/multi/samba/usermap_script",
        "label": "Samba usermap",
        "goal": "Get root shell via Samba",
        "rationale": "Samba detected",
    })
    try:
        result = orch._replan_from(g, "recon", log)
    finally:
        orch.call_llm = orig

    check("returns a new node id", result is not None)
    check("node was added", result in g.nodes)
    if result in g.nodes:
        n = g.nodes[result]
        check("module set", n.module == "exploit/multi/samba/usermap_script")
        check("RHOSTS = target_ip",
              n.module_options.get("RHOSTS") == "10.0.0.5")
        check("RPORT = 445 (samba)",
              n.module_options.get("RPORT") == 445)
        check("LHOST = attacker_ip",
              n.payload_options.get("LHOST") == "10.0.0.1")
        check("edge from recon to new node exists",
              any(e.source == "recon" and e.target == result for e in g.edges))


# -----------------------------------------------------------------------------
# Test 7 — _replan_from with run_commands intent end-to-end
# -----------------------------------------------------------------------------

def test_replan_run_commands_e2e():
    print("\n[Test 7] _replan_from end-to-end with run_commands intent")
    g = graph_with_session()
    log, _ = make_logger()
    orig = orch.call_llm
    orch.call_llm = llm_returning({
        "action": "run_commands",
        "target_hint": "id\nwhoami\ncat /etc/shadow",
        "label": "shadow dump",
        "goal": "Read shadow",
        "rationale": "have session",
    })
    try:
        result = orch._replan_from(g, "ssh_open", log)
    finally:
        orch.call_llm = orig

    check("returns a new node id", result is not None)
    if result and result in g.nodes:
        n = g.nodes[result]
        check("tool_name=session (session was open)",
              n.tool_name == "session")
        check("commands_to_run has 3 entries",
              len(n.commands_to_run) == 3,
              detail=f"got {len(n.commands_to_run)}")
        check("commands content correct",
              n.commands_to_run == ["id", "whoami", "cat /etc/shadow"])


# -----------------------------------------------------------------------------
# Test 8 — anti-repetition guard: same module as a FAILED node is rejected
# -----------------------------------------------------------------------------

def test_replan_rejects_repeat_module():
    print("\n[Test 8] _replan_from rejects a module already tried-and-failed")
    g = graph_no_session()
    log, _ = make_logger()

    # Pre-seed a failed node with the same module the LLM is about to propose
    failed = AttackNode(
        id="prior_attempt",
        label="prior usermap try",
        agent_type="exploit",
        module="exploit/multi/samba/usermap_script",
        target_ip="10.0.0.5",
    )
    failed.status = NodeStatus.FAILED.value
    failed.metadata["last_failure_reason"] = "Exploit completed but no session"
    g.add_node(failed)

    orig = orch.call_llm
    orch.call_llm = llm_returning({
        "action": "use_module",
        "target_hint": "exploit/multi/samba/usermap_script",  # same as failed
        "rationale": "trying samba",
    })
    try:
        result = orch._replan_from(g, "recon", log)
    finally:
        orch.call_llm = orig

    check("returns None (repeat rejected)", result is None,
          detail=f"got {result!r}")

    # Sanity: a DIFFERENT module IS accepted
    orch.call_llm = llm_returning({
        "action": "use_module",
        "target_hint": "exploit/unix/ftp/proftpd_modcopy_exec",  # not tried
        "rationale": "trying ftp",
    })
    try:
        result2 = orch._replan_from(g, "recon", log)
    finally:
        orch.call_llm = orig
    check("different module IS accepted", result2 is not None,
          detail=f"got {result2!r}")


# -----------------------------------------------------------------------------
# Test 9 — anti-repetition guard: same command set as FAILED node is rejected
# -----------------------------------------------------------------------------

def test_replan_rejects_repeat_commands():
    print("\n[Test 9] _replan_from rejects a command set already tried-and-failed")
    g = graph_with_session()
    log, _ = make_logger()

    failed = AttackNode(
        id="prior_cmd_node",
        label="prior dump attempt",
        agent_type="impact",
        tool_name="session",
        commands_to_run=["id", "cat /etc/shadow"],
        target_ip="10.0.0.5",
    )
    failed.status = NodeStatus.FAILED.value
    g.add_node(failed)

    orig = orch.call_llm
    orch.call_llm = llm_returning({
        "action": "run_commands",
        "target_hint": "id\ncat /etc/shadow",  # exact same commands
        "rationale": "trying again",
    })
    try:
        result = orch._replan_from(g, "ssh_open", log)
    finally:
        orch.call_llm = orig

    check("returns None (repeat rejected)", result is None,
          detail=f"got {result!r}")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Stage 4 offline correctness check")
    print("=" * 70)

    test_guess_rport()
    test_expand_use_module_fills_defaults()
    test_expand_run_commands_picks_tool()
    test_id_collision()
    test_malformed_intents()
    test_replan_use_module_e2e()
    test_replan_run_commands_e2e()
    test_replan_rejects_repeat_module()
    test_replan_rejects_repeat_commands()

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
