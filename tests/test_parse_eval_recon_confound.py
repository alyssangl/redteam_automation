"""Offline tests for the recon/root-failure confounder in parse_eval.

A recon (graph root) failure is a lab artifact (flaky target drops nmap packets),
not real system behavior: it cascades to every downstream node being `skipped`, so
the cell scores a spurious 0%. parse_eval must mark such a run `confounded=True`
(so build_table excludes it and the matrix resumes/retries it) — but ONLY for the
recon/root node failing, never for a run that recons fine and legitimately fails
later. These tests feed synthetic checkpoint dicts to the eval helpers, no lab.

Run:
    python tests/test_parse_eval_recon_confound.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.parse_eval import (
    _recon_or_root_failed, _root_node_ids, _parse_checkpoint,
)


def _cp(nodes, edges=None):
    return {"nodes": nodes, "edges": edges or [], "status": "completed"}


# --- structural root detection ------------------------------------------------

def test_root_is_node_with_no_incoming_edge():
    cp = _cp(
        {"recon": {"agent_type": "recon"}, "gain": {"agent_type": "exploit"}},
        [{"source": "recon", "target": "gain"}],
    )
    assert _root_node_ids(cp) == {"recon"}


# --- PRIMARY: recon-fail -> confounded ---------------------------------------

def test_recon_failed_is_confounded():
    # recon (root) failed; downstream skipped == the cascade we must exclude.
    cp = _cp(
        {
            "recon": {"agent_type": "recon", "status": "failed"},
            "gain_access": {"agent_type": "exploit", "status": "skipped"},
            "escalate": {"agent_type": "privesc", "status": "skipped"},
        },
        [{"source": "recon", "target": "gain_access"},
         {"source": "gain_access", "target": "escalate"}],
    )
    assert _recon_or_root_failed(cp) is True
    assert _parse_checkpoint(cp)["recon_confounded"] is True


def test_root_failed_even_if_not_named_recon():
    # root detected structurally (no incoming edge), even if agent_type differs.
    cp = _cp(
        {"entry": {"agent_type": "discovery", "status": "failed"},
         "next": {"agent_type": "exploit", "status": "skipped"}},
        [{"source": "entry", "target": "next"}],
    )
    assert _recon_or_root_failed(cp) is True


# --- NEGATIVE: recon fine, legitimate later failure -> NOT confounded ---------

def test_recon_success_objective_unmet_not_confounded():
    # recon succeeded but the run never reached the objective (pending) — REAL data.
    cp = _cp(
        {
            "recon": {"agent_type": "recon", "status": "success"},
            "gain_access": {"agent_type": "exploit", "status": "pending"},
            "escalate": {"agent_type": "privesc", "status": "pending"},
        },
        [{"source": "recon", "target": "gain_access"},
         {"source": "gain_access", "target": "escalate"}],
    )
    assert _recon_or_root_failed(cp) is False
    assert _parse_checkpoint(cp)["recon_confounded"] is False


def test_downstream_failure_not_confounded():
    # recon OK, a downstream (privesc) node failed — genuine system failure, counted.
    cp = _cp(
        {
            "recon": {"agent_type": "recon", "status": "success"},
            "gain_access": {"agent_type": "exploit", "status": "success"},
            "escalate": {"agent_type": "privesc", "status": "failed"},
        },
        [{"source": "recon", "target": "gain_access"},
         {"source": "gain_access", "target": "escalate"}],
    )
    assert _recon_or_root_failed(cp) is False


def test_all_success_not_confounded():
    cp = _cp(
        {"recon": {"agent_type": "recon", "status": "success"},
         "gain_access": {"agent_type": "exploit", "status": "success"}},
        [{"source": "recon", "target": "gain_access"}],
    )
    assert _recon_or_root_failed(cp) is False


def test_empty_checkpoint_not_confounded():
    # a truncated/empty checkpoint carries no recon signal (log side handles it).
    assert _recon_or_root_failed({}) is False
    assert _recon_or_root_failed({"nodes": {}}) is False


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
