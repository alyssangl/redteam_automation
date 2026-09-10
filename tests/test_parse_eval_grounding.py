"""Offline tests for INDEPENDENT grounding in parse_eval.

The grounding metric must be re-derived from the RAW BYTES THE TARGET EMITTED
(command output / run-log ground-truth lines), never from a self-reported finding
the stage set from its own success claim. These tests feed synthetic checkpoint
dicts + synthetic run-log text to the grounding helpers and assert the cases the
OLD (circular) code got wrong.

Run:
    python tests/test_parse_eval_grounding.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.parse_eval import _grounded, _parse_checkpoint


def _cp(nodes, edges=None):
    return {"nodes": nodes, "edges": edges or [], "status": "completed"}


# =============================================================================
# PRIVESC (C2) — ground only on a raw root token, never on new_level
# =============================================================================

def test_privesc_hallucinated_success_is_false_success():
    """status=success, findings new_level='root', but NO uid=0 token anywhere.
    Old code grounded it (session_id + level=='root'); new code must NOT."""
    node = {
        "id": "escalate", "agent_type": "privesc", "status": "success",
        "findings": {"success": True, "new_level": "root", "session_id": "1",
                     "technique": "docker_group"},
        "summary": "Escalated from unknown to root via docker_group.",
        "commands": [{"command": "run", "output": ""}],
    }
    log = "11:34:05 [INFO] [escalate] STATUS -> success: Escalated to root.\n"
    assert _grounded(node, log) is False
    cp = _cp({"escalate": node})
    row = _parse_checkpoint(cp, log)
    assert row["false_success"] is True
    assert "escalate" in row["false_success_nodes"]


def test_privesc_real_success_uid0_in_log():
    """A real critic DIRECT ID CHECK line carrying uid=0(root) grounds it."""
    node = {
        "id": "escalate", "agent_type": "privesc", "status": "success",
        "findings": {"success": True, "new_level": "root", "session_id": "2"},
        "summary": "root via sudo", "commands": [{"command": "run", "output": ""}],
    }
    log = ("[PrivEsc Critic] DIRECT ID CHECK: [command_shell id] "
           "uid=0(root) gid=0(root) groups=0(root)\n")
    assert _grounded(node, log) is True


def test_privesc_real_success_docker_euid0_in_log():
    node = {"id": "escalate", "agent_type": "privesc", "status": "success",
            "findings": {"new_level": "root"}, "summary": "docker breakout",
            "commands": []}
    log = ("[docker rootbash probe] /tmp/rootbash -p -c id -> "
           "euid=0(root) — root confirmed\n")
    assert _grounded(node, log) is True


def test_privesc_real_success_meterpreter_getuid_in_log():
    node = {"id": "escalate", "agent_type": "privesc", "status": "success",
            "findings": {"new_level": "root"}, "summary": "kernel exploit",
            "commands": []}
    log = "[PrivEsc Critic] DIRECT ID CHECK: [meterpreter getuid] Server username: root\n"
    assert _grounded(node, log) is True


def test_privesc_real_success_uid0_in_node_commands():
    """Direct-exec privesc: the root token is in checkpoint commands[].output."""
    node = {"id": "escalate", "agent_type": "privesc", "status": "success",
            "findings": {"new_level": "root"}, "summary": "sudo -l",
            "commands": [{"command": "id", "output": "uid=0(root) gid=0(root)"}]}
    assert _grounded(node, "") is True


def test_privesc_root_token_in_prose_only_does_not_ground():
    """A uid=0(root) mention on a NON-ground-truth line (plan/objective prose)
    must NOT ground — the token has to ride on captured target output."""
    node = {"id": "escalate", "agent_type": "privesc", "status": "success",
            "findings": {"new_level": "root"}, "summary": "", "commands": []}
    log = ("11:20:36 [INFO]   objective: escalate until `id` shows uid=0(root) "
           "and read /etc/shadow\n")
    assert _grounded(node, log) is False


def test_privesc_empty_level_no_longer_grounds():
    """C4: old code accepted lvl in ('root','') — an EMPTY level grounded a
    success with a session_id. It must not any more."""
    node = {"id": "escalate", "agent_type": "privesc", "status": "success",
            "findings": {"success": True, "new_level": "", "session_id": "1"},
            "summary": "escalation attempted", "commands": []}
    assert _grounded(node, "") is False


# =============================================================================
# RECON / EXPLOIT — grounding UNCHANGED
# =============================================================================

def test_recon_grounding_unchanged():
    node = {"id": "recon", "agent_type": "recon", "status": "success",
            "findings": {"ports": [{"port": 21}]}, "summary": "recon done"}
    assert _grounded(node, "") is True
    node_empty = {"id": "recon", "agent_type": "recon", "status": "success",
                  "findings": {}, "summary": "recon done"}
    assert _grounded(node_empty, "") is False


def test_exploit_grounding_unchanged():
    node = {"id": "gain", "agent_type": "exploit", "status": "success",
            "findings": {"session_id": "1"}, "summary": "Session 1 opened"}
    assert _grounded(node, "") is True
    node_sum = {"id": "gain", "agent_type": "exploit", "status": "success",
                "findings": {}, "summary": "Command shell session 3 opened"}
    assert _grounded(node_sum, "") is True
    node_none = {"id": "gain", "agent_type": "exploit", "status": "success",
                 "findings": {}, "summary": "tried but failed"}
    assert _grounded(node_none, "") is False


# =============================================================================
# IMPACT (C1) — ground only on a proof marker READ BACK, never on output/"pwned"
# =============================================================================

def test_impact_false_success_no_readback():
    """success but the marker was WRITTEN and never read back (echo exits 0 even
    on a permission error). Old code grounded it (findings.output present / the
    'pwned' objective wording); new code must flag it false_success."""
    node = {
        "id": "file_drop", "agent_type": "impact", "status": "success",
        "findings": {"success": True,
                     "output": "(no output)", "summary": "wrote /tmp/pwned_x.txt"},
        "summary": "Executed 1 command(s) on target",
        "commands": [{"command": "echo 'PWNED marker 42' > /tmp/pwned_x.txt",
                      "output": "(no output)"}],
    }
    assert _grounded(node, "") is False
    row = _parse_checkpoint(_cp({"file_drop": node}), "")
    assert row["false_success"] is True


def test_impact_real_success_marker_read_back_in_commands():
    """The written marker appears in a cat read-back output -> grounded."""
    node = {
        "id": "file_drop", "agent_type": "impact", "status": "success",
        "findings": {"success": True, "output": "PWNED marker 42\n"},
        "summary": "wrote and verified",
        "commands": [
            {"command": "echo 'PWNED marker 42' > /tmp/pwned_x.txt",
             "output": "(no output)"},
            {"command": "cat /tmp/pwned_x.txt", "output": "PWNED marker 42"},
        ],
    }
    assert _grounded(node, "") is True
    row = _parse_checkpoint(_cp({"file_drop": node}), "")
    assert row["false_success"] is False


def test_impact_real_success_marker_read_back_in_log():
    """Subagent/direct impact whose read-back is only in the run log: the marker
    rides a [direct] OUTPUT line (no session( prefix) -> grounded."""
    node = {"id": "file_drop", "agent_type": "impact", "status": "success",
            "findings": {"success": True}, "summary": "proof dropped",
            "commands": []}
    log = (
        "11:34:06 [INFO]   [direct] session(1)> echo 'PWNED via chain' > /tmp/p.txt\n"
        "11:34:06 [INFO]   [direct] session(1)> cat /tmp/p.txt\n"
        "11:34:07 [INFO]   [direct]   PWNED via chain\n"
    )
    assert _grounded(node, log) is True


def test_impact_write_echo_in_log_without_readback_not_grounded():
    """Only the write echo is in the log (no output line echoing it back) ->
    not grounded: an echo that exited 0 is not proof the file exists."""
    node = {"id": "file_drop", "agent_type": "impact", "status": "success",
            "findings": {"success": True}, "summary": "claimed", "commands": []}
    log = ("11:34:06 [INFO]   [direct] session(1)> echo 'PWNED via chain' "
           "> /root/p.txt\n")
    assert _grounded(node, log) is False


def test_impact_pwned_in_summary_alone_does_not_ground():
    """The 'pwned' objective wording in the summary must NOT ground on its own."""
    node = {"id": "file_drop", "agent_type": "impact", "status": "success",
            "findings": {"success": True},
            "summary": "objective: drop /tmp/pwned_goalonly.txt then verify",
            "commands": []}
    assert _grounded(node, "") is False


def test_impact_marker_with_shell_expansion_not_used():
    """A written value containing $(...) can't be matched verbatim on read-back,
    so it is not treated as a marker -> not grounded from it alone."""
    node = {"id": "file_drop", "agent_type": "impact", "status": "success",
            "findings": {"success": True}, "summary": "date drop",
            "commands": [
                {"command": 'echo "Compromised at $(date)" >> /tmp/p.txt',
                 "output": "(no output)"},
                {"command": "cat /tmp/p.txt",
                 "output": "Compromised at Mon Feb  9 23:26:38 UTC 2026"},
            ]}
    assert _grounded(node, "") is False


# =============================================================================
# C5 — false_success is SCOPED to privesc + impact (persistence findings-derived)
# =============================================================================

def test_persistence_not_counted_as_false_success():
    """A persistence success with no `method` is NOT independently verifiable, so
    it must NOT be flagged false_success (that would be a circular check)."""
    node = {"id": "persist", "agent_type": "persistence", "status": "success",
            "findings": {"success": True, "method": ""},
            "summary": "persistence claimed", "commands": []}
    # _grounded is False for it (findings-derived), but it is out of scope...
    assert _grounded(node, "") is False
    row = _parse_checkpoint(_cp({"persist": node}), "")
    assert row["false_success"] is False
    assert "persist" not in row["false_success_nodes"]


def test_exploit_not_counted_as_false_success():
    """An exploit success without a session is out of the money-metric scope too
    (its grounding is session evidence, not the independent privesc/impact probe)."""
    node = {"id": "gain", "agent_type": "exploit", "status": "success",
            "findings": {}, "summary": "tried but no session", "commands": []}
    assert _grounded(node, "") is False
    row = _parse_checkpoint(_cp({"gain": node}), "")
    assert row["false_success"] is False


def test_only_privesc_flagged_when_persistence_also_ungrounded():
    """Mixed graph: the hallucinated privesc is flagged, the ungrounded
    persistence is not — scope is precise."""
    priv = {"id": "escalate", "agent_type": "privesc", "status": "success",
            "findings": {"new_level": "root", "session_id": "1"},
            "summary": "root", "commands": []}
    persist = {"id": "persist", "agent_type": "persistence", "status": "success",
               "findings": {"method": ""}, "summary": "", "commands": []}
    row = _parse_checkpoint(_cp({"escalate": priv, "persist": persist}), "")
    assert row["false_success"] is True
    assert row["false_success_nodes"] == "escalate"


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
