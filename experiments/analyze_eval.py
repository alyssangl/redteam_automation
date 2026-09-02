"""
analyze_eval.py — statistics for the GRAFT paper (experiment_plan.md §8).

Reads the per-run CSV from parse_eval.py and prints the numbers Section V needs,
computed reproducibly with NO external stats dependency (pure-Python Wilson score
interval + two-sided Fisher exact):

  1. Per (scenario x variant): recovered and grounded k/n with a 95% Wilson interval.
  2. Headline contrast FULL vs NO-GRAFT on `recovered`, per orphan scenario AND
     pooled over all orphan placements, with a two-sided Fisher exact p.
  3. False-success (grounding) rate per variant.
  4. Cost: wall-seconds per grounded success per variant.
  5. Sanity: confounded / non-termination counts.

Confounded runs are excluded (lab artifacts), matching build_table.

Usage:
  python experiments/analyze_eval.py eval_results.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from math import comb, sqrt
from pathlib import Path

FULL, NOGRAFT = "v0_full", "v_nograft"


# --- pure-python statistics ---------------------------------------------------

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion k/n."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    # Clamp to [0,1] — a proportion CI cannot exceed those bounds (and floating
    # point can nudge an exact 0/1 endpoint just past them).
    return (max(0.0, (centre - margin) / denom), min(1.0, (centre + margin) / denom))


def fisher_exact_two_sided(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher exact p for the 2x2 table [[a,b],[c,d]] (fixed margins:
    sum of hypergeometric table probabilities <= the observed table's)."""
    n = a + b + c + d
    if n == 0:
        return 1.0
    row1, col1 = a + b, a + c

    def p_table(x: int) -> float:
        return comb(row1, x) * comb(n - row1, col1 - x) / comb(n, col1)

    p_obs = p_table(a)
    lo, hi = max(0, col1 - (n - row1)), min(row1, col1)
    total = sum(p_table(x) for x in range(lo, hi + 1)
                if p_table(x) <= p_obs * (1 + 1e-9))
    return min(1.0, total)


# --- CSV loading --------------------------------------------------------------

def _truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


def _load(csv_path: Path) -> list[dict]:
    with csv_path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return [r for r in rows if not _truthy(r.get("confounded"))]  # drop lab artifacts


def _counts(rows: list[dict], key: str) -> tuple[int, int]:
    """(successes, n) for a boolean metric column over the given rows."""
    n = len(rows)
    k = sum(1 for r in rows if _truthy(r.get(key)))
    return k, n


# --- report -------------------------------------------------------------------

def analyze(rows: list[dict]) -> str:
    out: list[str] = ["# GRAFT eval analysis\n"]
    by_cell: dict[tuple, list] = defaultdict(list)
    for r in rows:
        by_cell[(r["scenario"], r["variant"])].append(r)

    scenarios = sorted({s for s, _ in by_cell})
    variants = sorted({v for _, v in by_cell})

    out.append("## Per-cell recovered / grounded (k/n, 95% Wilson)\n")
    for s in scenarios:
        out.append(f"### {s}")
        for v in variants:
            cell = by_cell.get((s, v))
            if not cell:
                continue
            rk, rn = _counts(cell, "recovered")
            gk, gn = _counts(cell, "grounded_success")
            rlo, rhi = wilson(rk, rn)
            glo, ghi = wilson(gk, gn)
            out.append(f"  {v:12s}  recovered {rk}/{rn} "
                       f"[{rlo*100:4.0f},{rhi*100:4.0f}]%   "
                       f"grounded {gk}/{gn} [{glo*100:4.0f},{ghi*100:4.0f}]%")
        out.append("")

    # Headline: FULL vs NO-GRAFT recovery on orphan scenarios.
    out.append("## Headline contrast — FULL vs NO-GRAFT recovery (Fisher exact, 2-sided)\n")
    orphan = [s for s in scenarios if s.startswith("orphan")]
    pooled = {"fa": 0, "fn": 0, "na": 0, "nn": 0}
    for s in orphan:
        fk, fn = _counts(by_cell.get((s, FULL), []), "recovered")
        gk, gn = _counts(by_cell.get((s, NOGRAFT), []), "recovered")
        if fn and gn:
            p = fisher_exact_two_sided(fk, fn - fk, gk, gn - gk)
            out.append(f"  {s:12s}  FULL {fk}/{fn}  vs  NO-GRAFT {gk}/{gn}   p={p:.4g}")
            pooled["fa"] += fk; pooled["fn"] += fn - fk
            pooled["na"] += gk; pooled["nn"] += gn - gk
    if orphan and (pooled["fa"] + pooled["fn"]) and (pooled["na"] + pooled["nn"]):
        p = fisher_exact_two_sided(pooled["fa"], pooled["fn"], pooled["na"], pooled["nn"])
        fN = pooled["fa"] + pooled["fn"]; nN = pooled["na"] + pooled["nn"]
        out.append(f"  {'POOLED':12s}  FULL {pooled['fa']}/{fN}  vs  "
                   f"NO-GRAFT {pooled['na']}/{nN}   p={p:.4g}")
    out.append("")

    # Grounding: false-success rate per variant.
    out.append("## False-success rate per variant (grounding)\n")
    for v in variants:
        vr = [r for r in rows if r["variant"] == v]
        fk, fn = _counts(vr, "false_success")
        out.append(f"  {v:12s}  false-success {fk}/{fn}")
    out.append("")

    # Cost: wall-seconds per grounded success.
    out.append("## Cost — wall-seconds per grounded success per variant\n")
    for v in variants:
        vr = [r for r in rows if r["variant"] == v]
        gk, _ = _counts(vr, "grounded_success")
        wall = sum(float(r.get("wall_secs") or 0) for r in vr)
        per = f"{wall/gk:.0f}s" if gk else "n/a (0 grounded)"
        out.append(f"  {v:12s}  total {wall:.0f}s / {gk} grounded = {per}")
    out.append("")

    # Sanity.
    nt = sum(1 for r in rows if _truthy(r.get("non_termination")))
    out.append(f"## Sanity\n  valid runs: {len(rows)}   non-termination: {nt}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="GRAFT eval statistics from the run CSV.")
    ap.add_argument("csv", nargs="?", default="eval_results.csv")
    ap.add_argument("-o", "--out", default=None, help="also write the report here")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"CSV not found: {csv_path}")
        return 1
    rows = _load(csv_path)
    report = analyze(rows)
    print(report)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
