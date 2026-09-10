"""Integration test for the per-cell .stdout grounding-evidence capture.

A SUBAGENT-run privesc node (docker/kernel recovery) leaves its checkpoint
`commands` empty and emits its uid=0/euid=0 ground-truth via print()->stdout,
which the orchestrator's timestamped FileHandler .log does NOT capture. run_matrix
now saves that stdout to a per-cell `<tag>.stdout`, and parse_eval.evaluate_run
folds it into the GROUNDING evidence (only). This proves the round trip:

  - escalate claims success (findings.new_level="root") with NO token in the log
    or commands, and NO .stdout        -> false_success (conservative, correct)
  - same, but the .stdout carries `[grounded target output] euid=0(root)`
                                        -> grounded, NOT false_success

Run: python tests/test_parse_eval_stdout_evidence.py
"""
import sys, os, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path
from experiments import parse_eval as pe

# minimal completed flaw_privesc checkpoint: recon+access grounded, escalate is a
# SUBAGENT privesc success claiming root but with empty commands (token only ever
# in stdout).
_CP = {
    "status": "completed",
    "nodes": {
        "recon": {"agent_type": "recon", "status": "success",
                   "findings": {"ports": [22, 6667]}, "commands": []},
        "gain_access": {"agent_type": "exploit", "status": "success",
                         "findings": {"session_id": "1"}, "commands": []},
        "escalate": {"agent_type": "privesc", "status": "success",
                      "findings": {"new_level": "root"},   # self-report ONLY
                      "commands": []},
    },
    "edges": [{"source": "recon", "target": "gain_access"},
              {"source": "gain_access", "target": "escalate"}],
}

# a minimal per-run .log: timestamped markers only (NO ground-truth token here).
_LOG = (
    "22:00:01 [INFO] [Orchestrator] EXECUTION COMPLETE\n"
    "22:00:01 [INFO]   Status: completed\n"
    "22:00:01 [INFO]   Success rate: 100%\n"
    "22:00:01 [INFO]   ✓ escalate: Escalated to root via docker_group\n"
)

# the stages' print()->stdout ground-truth, as run_matrix would capture it.
_STDOUT_WITH_TOKEN = (
    "[PrivEsc Executor] TECHNIQUE: docker_group breakout\n"
    "[grounded target output] euid=0(root) -- root confirmed from target output\n"
)


def _write_cell(d: Path, tag: str, with_stdout: bool):
    (d / f"{tag}.json").write_text(json.dumps(_CP), encoding="utf-8")
    (d / f"{tag}.log").write_text(_LOG, encoding="utf-8")
    if with_stdout:
        (d / f"{tag}.stdout").write_text(_STDOUT_WITH_TOKEN, encoding="utf-8")


def test_subagent_root_grounded_via_stdout():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td); tag = "flaw_privesc__v0_full__r0"
        _write_cell(d, tag, with_stdout=True)
        row = pe.evaluate_run(d / f"{tag}.log", d / f"{tag}.json")
        assert row["grounded_success"] == "True" or row["grounded_success"] is True, row["grounded_success"]
        assert str(row["false_success"]).lower() in ("false", "0"), row["false_success"]


def test_subagent_root_false_success_without_stdout():
    # no .stdout -> the root token exists nowhere the parser can see -> the
    # self-reported new_level="root" must NOT ground it (the whole point).
    with tempfile.TemporaryDirectory() as td:
        d = Path(td); tag = "flaw_privesc__v0_full__r1"
        _write_cell(d, tag, with_stdout=False)
        row = pe.evaluate_run(d / f"{tag}.log", d / f"{tag}.json")
        assert str(row["false_success"]).lower() in ("true", "1"), \
            f"expected false_success without any root token, got {row['false_success']}"


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
