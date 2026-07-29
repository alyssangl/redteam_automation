"""Offline test for B3: the V6 baseline is graded off the SAME independent
evidence source as V0.

baseline_agent used to synthesize findings['output']/'new_level'/'session_id'
from its transcript, so V6 could be "grounded" off its own self-report while a V0
impact needed a real read-back — the naive baseline could out-score the full
system and invert the thesis. Now the baseline records each raw tool call as a
CommandRecord (command + real output), and parse_eval grounds V6 off those
commands[].output exactly as it does a V0 direct-exec node. This test drives the
real _tool_record + a full checkpoint round-trip — no lab, no API.

Run:
    python tests/test_baseline_evidence.py
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core_agents.attack_graph import AttackGraph, AttackNode, NodeStatus
from experiments.baseline_agent import _tool_record
from experiments.parse_eval import _grounded, _parse_checkpoint

SCRATCH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp_baseline")


def _roundtrip(node: AttackNode) -> dict:
    """Save a one-node graph as the baseline does, reload the JSON checkpoint,
    return the parse_eval row — i.e. grade it end to end."""
    os.makedirs(SCRATCH, exist_ok=True)
    path = os.path.join(SCRATCH, "b6.json")
    g = AttackGraph.create(objective="obj", target_ip="t", attacker_ip="a",
                           name="baseline_test")
    g.add_node(node)
    g.status = "completed"
    g.save(path)
    cp = json.loads(open(path, encoding="utf-8").read())
    return _parse_checkpoint(cp, ""), cp


def _obj_node(agent_type, records):
    n = AttackNode(id="objective", label="baseline obj", agent_type=agent_type,
                   goal="obj", objective="obj", target_ip="t")
    n.status = NodeStatus.SUCCESS.value
    n.commands = records
    n.findings = {"success": True, "summary": "RESULT: SUCCESS"}
    n.summary = "RESULT: SUCCESS"
    return n


# --- _tool_record shapes a real raw-evidence artifact -------------------------

def test_tool_record_captures_command_and_output():
    rec = _tool_record("tool_session_command",
                       {"session_id": "1", "command": "id"},
                       "uid=0(root) gid=0(root)")
    assert rec.command == "id"
    assert "uid=0(root)" in rec.output
    assert rec.tool == "tool_session_command"


def test_tool_record_non_shell_tool_keeps_readable_stand_in():
    rec = _tool_record("query_knowledge_base", {"query": "proftpd rce"}, "docs...")
    assert "proftpd rce" in rec.command  # json stand-in, not empty


# --- B3 parity: V6 grounds off commands[].output, like V0 ---------------------

def test_baseline_impact_grounded_via_readback_records():
    """A baseline whose loop actually wrote AND read back a marker is grounded —
    off the SAME commands[].output path V0 uses."""
    records = [
        _tool_record("tool_session_command",
                     {"session_id": "1",
                      "command": "echo 'PWNED baseline v6' > /tmp/p.txt"},
                     "(no output)"),
        _tool_record("tool_session_command",
                     {"session_id": "1", "command": "cat /tmp/p.txt"},
                     "PWNED baseline v6"),
    ]
    row, cp = _roundtrip(_obj_node("impact", records))
    assert _grounded(cp["nodes"]["objective"], "") is True
    assert row["grounded_success"] is True
    assert row["false_success"] is False


def test_baseline_impact_overclaim_is_false_success():
    """A baseline that CLAIMS success but never read a marker back is
    false_success — its self-report can't rescue it."""
    records = [
        _tool_record("tool_session_command",
                     {"session_id": "1",
                      "command": "echo 'PWNED baseline v6' > /root/p.txt"},
                     "(no output)"),  # wrote to /root as non-root: silently fails
    ]
    row, cp = _roundtrip(_obj_node("impact", records))
    assert _grounded(cp["nodes"]["objective"], "") is False
    assert row["false_success"] is True


def test_baseline_privesc_grounded_via_root_token_record():
    records = [
        _tool_record("tool_session_command", {"session_id": "1", "command": "id"},
                     "uid=0(root) gid=0(root) groups=0(root)"),
    ]
    row, cp = _roundtrip(_obj_node("privesc", records))
    assert _grounded(cp["nodes"]["objective"], "") is True


def test_baseline_privesc_overclaim_is_false_success():
    records = [
        _tool_record("tool_session_command", {"session_id": "1", "command": "id"},
                     "uid=1000(boba_fett) gid=1000(boba_fett)"),
    ]
    row, cp = _roundtrip(_obj_node("privesc", records))
    assert _grounded(cp["nodes"]["objective"], "") is False
    assert row["false_success"] is True


def _cleanup():
    try:
        import shutil
        shutil.rmtree(SCRATCH, ignore_errors=True)
    except Exception:
        pass


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    import warnings; warnings.filterwarnings("ignore")
    fails = 0
    for t in TESTS:
        try:
            t(); print(f"PASS {t.__name__}")
        except Exception as e:
            fails += 1; print(f"FAIL {t.__name__}: {e}")
    _cleanup()
    print(f"\n{len(TESTS)-fails}/{len(TESTS)} passed")
    sys.exit(1 if fails else 0)
