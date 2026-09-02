"""Offline tests for the run_eval end-to-end driver.

No lab, no runs. Guards the two things that matter for an unattended launch:
  1. the paper defaults are the intended minimal matrix, and every default
     variant actually exists in run_matrix.VARIANTS, and
  2. the safe paths (--dry-run, unknown-variant validation) NEVER invoke the
     matrix (which would spawn lab subprocesses). We assert this by monkeypatching
     run_matrix._run_matrix to blow up if it is ever called on those paths.

Run:
    python tests/test_run_eval_plan.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments import run_eval, run_matrix


def _boom(*a, **k):
    raise AssertionError("run_matrix._run_matrix was called on a no-lab path!")


def _run_main(argv):
    orig_argv = sys.argv
    sys.argv = ["run_eval.py"] + argv
    try:
        return run_eval.main()
    finally:
        sys.argv = orig_argv


def test_paper_defaults_are_the_minimal_matrix():
    assert run_eval.PAPER_SCENARIOS == ["flaw_persistence", "flaw_privesc"]
    assert run_eval.PAPER_REPS == 5
    # both contributions represented: replanner (flaw_persistence) + grounding floor
    assert "v0_full" in run_eval.PAPER_VARIANTS
    assert "v1_noreplan" in run_eval.PAPER_VARIANTS
    assert "v3_noground" in run_eval.PAPER_VARIANTS
    assert "v6_naive" in run_eval.PAPER_VARIANTS


def test_every_default_variant_is_known():
    for v in run_eval.PAPER_VARIANTS:
        assert v in run_matrix.VARIANTS, f"{v} not in run_matrix.VARIANTS"


def test_dry_run_never_touches_the_lab():
    orig = run_matrix._run_matrix
    run_matrix._run_matrix = _boom
    try:
        rc = _run_main(["--dry-run"])
        assert rc == 0
    finally:
        run_matrix._run_matrix = orig


def test_unknown_variant_is_rejected_before_any_run():
    orig = run_matrix._run_matrix
    run_matrix._run_matrix = _boom
    try:
        rc = _run_main(["--variants", "v0_full", "v99_bogus"])
        assert rc == 2  # validation error, and _boom never fired
    finally:
        run_matrix._run_matrix = orig


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
