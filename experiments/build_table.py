"""
build_table.py — aggregate eval_results.csv into the ablation table (the paper).

Reads the per-run CSV emitted by parse_eval.py and produces:
  - reports/ablation_table.md      — headline table: rows=variants, cols=metrics,
                                      each cell = mean +/- std over all runs of that
                                      variant (across scenarios x reps).
  - reports/eval_per_scenario.md   — the same metrics broken out per scenario, so
                                      you can see WHICH scenarios each variant fails.

The story the table should tell (docs/plans/eval_benchmark.md): remove grounding
(v3) -> false_success spikes; remove replanner (v1) -> recovered collapses; remove
determinism (v4) -> non_termination rises.

Usage:
  python experiments/parse_eval.py --eval-dir logs/eval -o eval_results.csv
  python experiments/build_table.py eval_results.csv
"""

from __future__ import annotations

import argparse
import csv
import math
from collections import defaultdict
from pathlib import Path

# Rate metrics (0/1 per run) reported as mean +/- std, and mean-only numerics.
_RATE_METRICS = [
    ("grounded_success", "Grounded success"),
    ("false_success", "False success"),
    ("recovered", "Recovery (flaw_*)"),
    ("non_termination", "Non-termination"),
]
_NUMERIC_METRICS = [
    ("replan_edits", "Replan edits"),
    ("wall_secs", "Wall secs"),
]

# Preferred variant ordering for the table rows.
_VARIANT_ORDER = ["v0_full", "v1_noreplan", "v2_nojudge", "v3_noground",
                  "v4_nodeterm", "v5_norag", "v6_naive"]


def _as_bool(v: str) -> float:
    return 1.0 if str(v).strip().lower() in ("true", "1", "yes") else 0.0


def _as_float(v: str) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _mean_std(xs: list[float]) -> tuple[float, float]:
    if not xs:
        return 0.0, 0.0
    m = sum(xs) / len(xs)
    if len(xs) < 2:
        return m, 0.0
    var = sum((x - m) ** 2 for x in xs) / (len(xs) - 1)
    return m, math.sqrt(var)


def _fmt_rate(xs: list[float]) -> str:
    m, s = _mean_std(xs)
    return f"{m*100:.0f}% ± {s*100:.0f}"


def _fmt_num(xs: list[float]) -> str:
    m, s = _mean_std(xs)
    return f"{m:.1f} ± {s:.1f}"


def _load(csv_path: Path) -> tuple[list[dict], int]:
    """Return (valid rows, discarded-confounded count). Confounded cells
    (wedged-msfrpcd timeouts) are excluded from the metrics per eval_benchmark.md
    §7 — they are lab artifacts, not system behavior."""
    with csv_path.open(encoding="utf-8") as fh:
        all_rows = list(csv.DictReader(fh))
    valid = [r for r in all_rows if str(r.get("confounded", "")).strip().lower()
             not in ("true", "1", "yes")]
    return valid, len(all_rows) - len(valid)


def _variant_sort_key(v: str) -> tuple[int, str]:
    return (_VARIANT_ORDER.index(v) if v in _VARIANT_ORDER else 99, v)


def _table(rows: list[dict], flaw_only_recovery: bool = True) -> str:
    """One markdown table: variants x metrics, aggregated over the given rows."""
    by_variant: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_variant[r["variant"]].append(r)

    headers = ["Variant", "N"] + [lbl for _, lbl in _RATE_METRICS] \
        + [lbl for _, lbl in _NUMERIC_METRICS]
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join(["---"] * len(headers)) + "|"]

    for variant in sorted(by_variant, key=_variant_sort_key):
        vrows = by_variant[variant]
        cells = [variant, str(len(vrows))]
        for key, _ in _RATE_METRICS:
            # recovery is only defined on flaw_* scenarios; restrict its sample
            if key == "recovered" and flaw_only_recovery:
                sample = [r for r in vrows if r["scenario"].startswith("flaw")]
            else:
                sample = vrows
            cells.append(_fmt_rate([_as_bool(r[key]) for r in sample]) if sample else "-")
        for key, _ in _NUMERIC_METRICS:
            cells.append(_fmt_num([_as_float(r[key]) for r in vrows]))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def build_headline(rows: list[dict], discarded: int = 0) -> str:
    out = ["# Ablation table\n",
           "_Rows = system variants, cols = metrics. Each cell = mean ± std over "
           "all runs of that variant (scenarios × reps). Recovery is computed over "
           "flaw_* scenarios only._\n",
           f"_Source: {len(rows)} valid runs"
           + (f"; {discarded} confounded run(s) discarded (wedged-msfrpcd "
              "timeouts, excluded per protocol)." if discarded else ".") + "_\n",
           _table(rows),
           "\n\n## Reading it\n",
           "- **v3_noground** should show **False success** spiking vs v0_full "
           "(grounding is what suppresses unproven claims).",
           "- **v1_noreplan** should show **Recovery** collapsing (the replanner "
           "is what restructures around the injected failure).",
           "- **v4_nodeterm** should show **Non-termination** rising (deterministic "
           "tried-tracking is what prevents technique loops).",
           "- **v6_naive** is the external floor: no graph, judge, or replanner.\n"]
    return "\n".join(out)


def build_per_scenario(rows: list[dict]) -> str:
    by_scenario: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_scenario[r["scenario"]].append(r)
    out = ["# Per-scenario breakdown\n",
           "_Same metrics as the headline table, split by scenario — shows which "
           "scenarios each variant fails._\n"]
    for scenario in sorted(by_scenario):
        out.append(f"\n## {scenario}\n")
        out.append(_table(by_scenario[scenario], flaw_only_recovery=False))
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Aggregate eval CSV into the ablation table.")
    ap.add_argument("csv", nargs="?", default="eval_results.csv")
    ap.add_argument("--out-dir", default="reports")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"CSV not found: {csv_path}")
        return 1
    rows, discarded = _load(csv_path)
    if not rows:
        print(f"no valid rows in CSV ({discarded} confounded discarded)")
        return 1

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    headline = out_dir / "ablation_table.md"
    per_scen = out_dir / "eval_per_scenario.md"
    headline.write_text(build_headline(rows, discarded), encoding="utf-8")
    per_scen.write_text(build_per_scenario(rows), encoding="utf-8")

    print(f"wrote {headline} and {per_scen} from {len(rows)} valid runs "
          f"({discarded} confounded discarded)")
    print()
    print(build_headline(rows, discarded))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
