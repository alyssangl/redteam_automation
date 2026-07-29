"""Offline test for C3: build_table reports the confounded/excluded COUNT per
(scenario × variant) cell, not just a global total — so a reviewer can see the
exclusion is not concentrated in the variant whose metric we claim.

Also checks the threats-to-validity note is emitted (C5 persistence + subagent
capture). Pure string/dict assertions — no lab, no API.

Run:
    python tests/test_build_table_exclusion.py
"""
import sys, os, csv, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.build_table import (
    _load, _is_confounded, _exclusion_section, _threats_to_validity,
    build_headline,
)


def _row(scenario, variant, confounded=False, **kw):
    r = {"scenario": scenario, "variant": variant,
         "confounded": "true" if confounded else "false",
         "grounded_success": "true", "false_success": "false",
         "recovered": "false", "non_termination": "false",
         "replan_edits": "0", "wall_secs": "10"}
    r.update(kw)
    return r


def test_load_returns_all_rows_and_valid(tmpfile=None):
    rows = [_row("flaw_privesc", "v0_full"),
            _row("flaw_privesc", "v3_noground", confounded=True),
            _row("goal_only", "v0_full")]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    w.writeheader()
    for r in rows:
        w.writerow(r)
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp_excl.csv")
    open(path, "w", newline="", encoding="utf-8").write(buf.getvalue())
    try:
        valid, all_rows = _load(__import__("pathlib").Path(path))
        assert len(all_rows) == 3
        assert len(valid) == 2  # the confounded one dropped
    finally:
        os.remove(path)


def test_exclusion_section_has_per_cell_counts():
    all_rows = [
        _row("flaw_privesc", "v0_full"),
        _row("flaw_privesc", "v0_full", confounded=True),
        _row("flaw_privesc", "v0_full", confounded=True),
        _row("goal_only", "v4_nodeterm", confounded=True),
        _row("goal_only", "v3_noground"),
    ]
    sec = _exclusion_section(all_rows)
    # a per (scenario × variant) matrix with a scenario row + variant columns
    assert "Scenario \\ Variant" in sec
    assert "flaw_privesc" in sec and "goal_only" in sec
    assert "v0_full" in sec and "v4_nodeterm" in sec
    # v0_full had 2 exclusions in flaw_privesc -> a "2" cell + per-variant total
    assert "2" in sec
    assert "excluded / variant" in sec
    # concentration verdict names the most-excluded variant and v3_noground's count
    assert "Most-excluded variant" in sec
    assert "v3_noground" in sec


def test_exclusion_concentration_flags_v3_when_it_dominates():
    all_rows = [
        _row("s1", "v3_noground", confounded=True),
        _row("s1", "v3_noground", confounded=True),
        _row("s1", "v0_full", confounded=True),
        _row("s1", "v0_full"),
    ]
    sec = _exclusion_section(all_rows)
    # v3_noground is the most-excluded here -> the note must warn, not reassure
    assert "investigate exclusion bias" in sec


def test_exclusion_reassures_when_v3_not_dominant():
    all_rows = [
        _row("s1", "v4_nodeterm", confounded=True),
        _row("s1", "v4_nodeterm", confounded=True),
        _row("s1", "v3_noground", confounded=True),
        _row("s1", "v0_full"),
    ]
    sec = _exclusion_section(all_rows)
    assert "no exclusion bias toward the grounding claim" in sec


def test_no_exclusions_reported_cleanly():
    all_rows = [_row("s1", "v0_full"), _row("s1", "v3_noground")]
    sec = _exclusion_section(all_rows)
    assert "No cells excluded" in sec


def test_threats_to_validity_covers_persistence_and_capture():
    t = _threats_to_validity()
    assert "Persistence grounding is findings-derived" in t
    assert "scoped" in t.lower() or "SCOPED" in t
    assert "Subagent ground-truth capture" in t


def test_build_headline_includes_exclusion_and_threats():
    valid = [_row("flaw_privesc", "v0_full")]
    all_rows = valid + [_row("flaw_privesc", "v3_noground", confounded=True)]
    md = build_headline(valid, all_rows)
    assert "Confounded / excluded cells" in md
    assert "Threats to validity" in md
    # global count still mentioned, now points at the per-cell breakdown
    assert "1 confounded run(s) discarded" in md


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
