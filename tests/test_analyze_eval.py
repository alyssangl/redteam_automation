"""Offline tests for the GRAFT analysis stats (build step 6).

Pins the pure-Python Wilson interval + two-sided Fisher exact against the values
the experiment plan quotes (§8: 8/10 vs 0/10 -> p=0.0007; 4/10 vs 0/10 -> p=0.087,
not significant; pooled 21/30 vs 0/30 -> p ~ 3.6e-9), and runs the end-to-end
report over a synthetic CSV with no lab.

Run:
    python tests/test_analyze_eval.py
"""
import sys, os, csv, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.analyze_eval import (
    wilson, fisher_exact_two_sided, _load, analyze,
)


def test_wilson_basic():
    lo, hi = wilson(8, 10)
    assert 0.0 <= lo < 0.8 < hi <= 1.0
    assert wilson(0, 10)[0] == 0.0            # k=0 -> lower bound 0
    assert wilson(0, 0) == (0.0, 0.0)         # empty guarded


def test_fisher_matches_plan_quotes():
    # experiment_plan.md §8 reference values
    p_8_0 = fisher_exact_two_sided(8, 2, 0, 10)
    assert abs(p_8_0 - 0.0007) < 5e-4, p_8_0        # ~0.0007, significant
    p_4_0 = fisher_exact_two_sided(4, 6, 0, 10)
    assert p_4_0 > 0.05, p_4_0                        # ~0.087, NOT significant
    p_pooled = fisher_exact_two_sided(21, 9, 0, 30)
    assert p_pooled < 1e-6, p_pooled                 # ~3.6e-9


def test_fisher_symmetric_and_bounded():
    assert fisher_exact_two_sided(5, 5, 5, 5) == 1.0     # identical arms -> p=1
    assert 0.0 <= fisher_exact_two_sided(10, 0, 0, 10) <= 1.0


def _write_csv(path, rows):
    cols = ["scenario", "variant", "confounded", "recovered",
            "grounded_success", "false_success", "non_termination", "wall_secs"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def test_end_to_end_report_and_confounded_excluded():
    rows = []
    # FULL recovers 8/10 on orphan-A; NO-GRAFT 0/10; plus one confounded FULL row.
    for i in range(10):
        rows.append({"scenario": "orphan_a", "variant": "v0_full", "confounded": "False",
                     "recovered": str(i < 8), "grounded_success": str(i < 8),
                     "false_success": "False", "non_termination": "False", "wall_secs": "1000"})
        rows.append({"scenario": "orphan_a", "variant": "v_nograft", "confounded": "False",
                     "recovered": "False", "grounded_success": "False",
                     "false_success": "False", "non_termination": "False", "wall_secs": "800"})
    rows.append({"scenario": "orphan_a", "variant": "v0_full", "confounded": "True",
                 "recovered": "False", "grounded_success": "False",
                 "false_success": "False", "non_termination": "True", "wall_secs": "2400"})

    fd, path = tempfile.mkstemp(suffix=".csv"); os.close(fd)
    try:
        _write_csv(path, rows)
        from pathlib import Path
        loaded = _load(Path(path))
        assert len(loaded) == 20                 # confounded row dropped
        report = analyze(loaded)
        assert "FULL 8/10" in report and "NO-GRAFT 0/10" in report
        assert "orphan_a" in report
    finally:
        os.remove(path)


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
