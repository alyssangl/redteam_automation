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
_VARIANT_ORDER = ["v0_full", "v_nograft", "v1_noreplan", "v2_nojudge",
                  "v3_noground", "v4_nodeterm", "v5_norag", "v6_naive"]


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


def _is_confounded(r: dict) -> bool:
    return str(r.get("confounded", "")).strip().lower() in ("true", "1", "yes")


def _load(csv_path: Path) -> tuple[list[dict], list[dict]]:
    """Return (valid rows, ALL rows). Confounded cells (wedged-msfrpcd timeouts,
    recon/root failures) are excluded from the metrics per eval_benchmark.md §7 —
    they are lab artifacts, not system behavior. ALL rows are returned too so the
    exclusion can be reported per (scenario × variant), not just as a global total
    (C3: a reviewer must be able to see the exclusion is not concentrated in the
    variant whose metric we claim)."""
    with csv_path.open(encoding="utf-8") as fh:
        all_rows = list(csv.DictReader(fh))
    valid = [r for r in all_rows if not _is_confounded(r)]
    return valid, all_rows


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
            # recovery is only defined on injected-fault scenarios (flaw_* technique
            # failures + orphan_* capability losses); restrict its sample to those
            if key == "recovered" and flaw_only_recovery:
                sample = [r for r in vrows
                          if r["scenario"].startswith(("flaw", "orphan"))]
            else:
                sample = vrows
            cells.append(_fmt_rate([_as_bool(r[key]) for r in sample]) if sample else "-")
        for key, _ in _NUMERIC_METRICS:
            cells.append(_fmt_num([_as_float(r[key]) for r in vrows]))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _exclusion_section(all_rows: list[dict]) -> str:
    """C3 — confounded/excluded COUNT per (scenario × variant), so a reviewer can
    confirm the exclusion is not concentrated in the grounding-claim variant."""
    confounded = [r for r in all_rows if _is_confounded(r)]
    lines = ["## Confounded / excluded cells\n",
             f"_{len(confounded)} of {len(all_rows)} run(s) excluded as lab "
             "artifacts (wedged-msfrpcd timeouts, recon/root-node failures), shown "
             "per (scenario × variant). A reviewer should confirm the exclusions "
             "are NOT concentrated in the variant whose metric we claim "
             "(v3_noground for false_success)._\n"]
    if not confounded:
        lines.append("_No cells excluded._")
        return "\n".join(lines)

    scenarios = sorted({r.get("scenario", "?") for r in all_rows})
    variants = sorted({r.get("variant", "?") for r in all_rows},
                      key=_variant_sort_key)
    cnt: dict[tuple[str, str], int] = defaultdict(int)
    vtot: dict[str, int] = defaultdict(int)
    for r in confounded:
        cnt[(r.get("scenario", "?"), r.get("variant", "?"))] += 1
        vtot[r.get("variant", "?")] += 1

    header = ["Scenario \\ Variant"] + variants
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join(["---"] * len(header)) + "|")
    for s in scenarios:
        cells = [s] + [str(cnt[(s, v)]) if cnt[(s, v)] else "·" for v in variants]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("| **excluded / variant** | "
                 + " | ".join(f"**{vtot[v]}**" for v in variants) + " |")

    worst_v, worst_n = max(vtot.items(), key=lambda kv: kv[1])
    claim_n = vtot.get("v3_noground", 0)
    verdict = ("NOT the most-excluded — no exclusion bias toward the grounding "
               "claim." if worst_v != "v3_noground"
               else "also the most-excluded — investigate exclusion bias.")
    lines.append(f"\n_Most-excluded variant: **{worst_v}** ({worst_n} run(s)). "
                 f"v3_noground has {claim_n} exclusion(s) — {verdict}_")
    return "\n".join(lines)


def _threats_to_validity() -> str:
    return "\n".join([
        "## Threats to validity\n",
        "- **Persistence grounding is findings-derived (C5).** privesc and impact "
        "have cheap INDEPENDENT probes (root `id`/`getuid`; a proof-marker read "
        "back off the target), but a landed cron/ssh-key/service does not, so its "
        "grounding rests on the stage's own findings. `false_success` is therefore "
        "SCOPED to privesc+impact; a persistence over-claim is not counted. Widen "
        "only once persistence can be grounded independently.",
        "- **Subagent ground-truth capture.** When privesc/impact run as subagents "
        "their raw root/probe output is emitted to stdout, which the per-run file "
        "log does not capture (it lands in the combined matrix stdout). For those "
        "nodes the per-run artifacts can lack the token, so a real escalation may "
        "be scored `false_success`. The bias is CONSERVATIVE (never over-credits a "
        "claim); routing subagent ground-truth into the per-run log would tighten "
        "it.",
        "- **Exclusions.** Confounded cells are dropped as lab artifacts; the "
        "per-cell table above lets a reviewer confirm the drops are not "
        "concentrated in the grounding-claim variant.\n",
    ])


def build_headline(rows: list[dict], all_rows: list[dict] | None = None) -> str:
    all_rows = all_rows if all_rows is not None else list(rows)
    discarded = sum(1 for r in all_rows if _is_confounded(r))
    variants_present = sorted({r["variant"] for r in rows}, key=_variant_sort_key)
    out = ["# Ablation table\n",
           "_Rows = system variants, cols = metrics. Each cell = mean ± std over "
           "all runs of that variant, POOLED across scenarios × reps._\n",
           "> **Read the per-scenario table (`eval_per_scenario.md`) for the "
           "headline.** Recovery is only comparable WITHIN a scenario — pooling it "
           "here mixes scenarios with different objectives (e.g. a deterministic "
           "impact objective vs. a technique-failure control), so the pooled "
           "recovery figure is diluted and not the number to quote.\n",
           f"_Source: {len(rows)} valid runs"
           + (f"; {discarded} confounded run(s) discarded (wedged-msfrpcd "
              "timeouts / recon-root failures, excluded per protocol — see the "
              "per-cell breakdown below)." if discarded else ".") + "_\n",
           _table(rows),
           "\n\n## Reading it\n",
           "- **Recovery** is the headline metric for the graft — but read it "
           "**per scenario** (above it is pooled). On a capability-loss (orphan_*) "
           "scenario, **v0_full** should recover and **v_nograft** should not; on a "
           "technique-failure (flaw_*) control the two should behave alike.",
           "- **False success** is re-derived from INDEPENDENT evidence (a root "
           "token / a proof-marker read back off the target), never the agent's own "
           "findings, and is scoped to privesc+impact. Grounded variants hold it at "
           "0; a grounding-OFF variant (v3_noground / v6_naive) is where it spikes.",
           "- **Non-termination** is capped by the replan budget; deterministic "
           "tried-tracking is what keeps it low.\n",
           f"_Variants in this run: {', '.join(variants_present)}._\n",
           _exclusion_section(all_rows),
           "\n",
           _threats_to_validity()]
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
    rows, all_rows = _load(csv_path)
    discarded = len(all_rows) - len(rows)
    if not rows:
        print(f"no valid rows in CSV ({discarded} confounded discarded)")
        return 1

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    headline = out_dir / "ablation_table.md"
    per_scen = out_dir / "eval_per_scenario.md"
    headline.write_text(build_headline(rows, all_rows), encoding="utf-8")
    per_scen.write_text(build_per_scenario(rows), encoding="utf-8")

    print(f"wrote {headline} and {per_scen} from {len(rows)} valid runs "
          f"({discarded} confounded discarded)")
    print()
    print(build_headline(rows, all_rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
