"""
run_eval.py — ONE command to run the paper's ablation end-to-end.

This chains the three existing pieces so a busy operator (or a successor taking
the project over) never has to remember the sequence:

    1. run_matrix   — run every (scenario x variant x rep) cell as an isolated,
                      msf-clean, timeout-guarded subprocess. RESUMABLE: a re-launch
                      skips cells that already have a clean result and retries the
                      confounded ones, so you can Ctrl-C and come back.
    2. parse_eval   — turn each finished run into one deterministic CSV row
                      (grounded_success / false_success / recovered / ... ), with
                      lab-artifact cells flagged confounded.
    3. build_table  — aggregate the CSV into reports/ablation_table.md and
                      reports/eval_per_scenario.md (the paper's tables).

The DEFAULTS are the minimal matrix the Oct-2 submission needs: the two recovery
scenarios that support both contributions (flaw_persistence for the replanner,
flaw_privesc for grounding), the four ablations + the naive floor, N=5.

Typical use (bring the lab up first — see HANDOFF.md 4.3):

    # preview the plan, touch nothing (no lab needed):
    python experiments/run_eval.py --dry-run

    # the real thing — run it detached and walk away (~a few nights of compute):
    #   Windows PowerShell:
    #     Start-Process -NoNewWindow python "experiments/run_eval.py" -RedirectStandardOutput logs/eval/_run.out
    #   bash / nohup:
    #     nohup python experiments/run_eval.py > logs/eval/_run.out 2>&1 &
    python experiments/run_eval.py

    # just rebuild the CSV + tables from whatever runs already exist (no lab):
    python experiments/run_eval.py --parse-only

You can override any of the matrix knobs (--scenarios/--variants/--reps/--target
/--timeout/--no-restart); they pass straight through to run_matrix.
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from experiments import run_matrix, parse_eval, build_table  # noqa: E402

# The minimal matrix the paper needs (see module docstring).
PAPER_SCENARIOS = ["flaw_persistence", "flaw_privesc"]
PAPER_VARIANTS = ["v0_full", "v1_noreplan", "v3_noground", "v4_nodeterm", "v6_naive"]
PAPER_REPS = 5


def _parse_phase(eval_dir: Path, csv_path: Path) -> int:
    """parse_eval over every run pair in eval_dir -> csv_path. Returns row count."""
    pairs = parse_eval._pair_up(eval_dir)
    if not pairs:
        print(f"[parse] no run pairs in {eval_dir} yet — nothing to parse.")
        return 0
    rows = []
    for log_path, cp_path in pairs:
        try:
            rows.append(parse_eval.evaluate_run(log_path, cp_path))
        except Exception as e:  # one bad run must not sink the batch
            print(f"[parse] [error] {log_path.name}: {e}", file=sys.stderr)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=parse_eval._COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[parse] wrote {csv_path} ({len(rows)} run row(s))")
    return len(rows)


def _build_phase(csv_path: Path, out_dir: Path) -> bool:
    """build_table over the CSV -> reports/*.md. Returns True if tables written."""
    if not csv_path.exists():
        print(f"[build] no CSV at {csv_path} — skipping table build.")
        return False
    rows, all_rows = build_table._load(csv_path)
    discarded = len(all_rows) - len(rows)
    if not rows:
        print(f"[build] no valid rows ({discarded} confounded) — no tables written yet.")
        return False
    out_dir.mkdir(parents=True, exist_ok=True)
    headline = out_dir / "ablation_table.md"
    per_scen = out_dir / "eval_per_scenario.md"
    headline.write_text(build_table.build_headline(rows, all_rows), encoding="utf-8")
    per_scen.write_text(build_table.build_per_scenario(rows), encoding="utf-8")
    print(f"[build] wrote {headline} and {per_scen} "
          f"({len(rows)} valid, {discarded} confounded/excluded)")
    return True


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(
        description="Run the paper ablation end-to-end (matrix -> parse -> tables).")
    ap.add_argument("--scenarios", nargs="+", default=PAPER_SCENARIOS)
    ap.add_argument("--variants", nargs="+", default=PAPER_VARIANTS)
    ap.add_argument("--reps", type=int, default=PAPER_REPS)
    ap.add_argument("--target", default=run_matrix.DEFAULT_TARGET)
    ap.add_argument("--attacker", default=run_matrix.DEFAULT_ATTACKER)
    ap.add_argument("--timeout", type=int, default=run_matrix.DEFAULT_TIMEOUT,
                    help="per-cell wall-clock ceiling (seconds)")
    ap.add_argument("--no-restart", action="store_true",
                    help="skip restart_msf before each cell")
    ap.add_argument("--eval-dir", default=str(run_matrix.EVAL_DIR))
    ap.add_argument("--csv", default="eval_results.csv")
    ap.add_argument("--out-dir", default="reports")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the matrix plan and exit (no lab, no parsing)")
    ap.add_argument("--parse-only", action="store_true",
                    help="skip the runs; just (re)build the CSV + tables from "
                         "existing logs (no lab needed)")
    args = ap.parse_args()

    unknown = [v for v in args.variants if v not in run_matrix.VARIANTS]
    if unknown:
        print(f"unknown variant(s): {unknown}\n known: {list(run_matrix.VARIANTS)}",
              file=sys.stderr)
        return 2

    eval_dir = Path(args.eval_dir)
    csv_path = Path(args.csv)
    out_dir = Path(args.out_dir)

    if args.dry_run:
        total = len(args.scenarios) * len(args.variants) * args.reps
        est_h = total * 20 / 60.0  # ~20 min/cell rough compute estimate
        run_matrix._dry_run(args.scenarios, args.variants, args.reps)
        print(f"\nAfter the matrix: parse_eval -> {csv_path}, "
              f"build_table -> {out_dir}/ablation_table.md (+ per-scenario).")
        print(f"Rough compute if every cell runs fresh: ~{est_h:.0f}h "
              f"(resumable; completed cells are skipped on relaunch).")
        return 0

    started = time.time()

    if not args.parse_only:
        print(f"===== run_eval: MATRIX PHASE "
              f"({len(args.scenarios)}x{len(args.variants)}x{args.reps} cells) =====",
              flush=True)
        run_matrix._run_matrix(
            args.scenarios, args.variants, args.reps,
            args.target, args.attacker, args.timeout,
            restart=not args.no_restart, skip_done=True,
        )
    else:
        print("===== run_eval: PARSE-ONLY (skipping the matrix) =====", flush=True)

    print("\n===== run_eval: PARSE PHASE =====", flush=True)
    _parse_phase(eval_dir, csv_path)

    print("\n===== run_eval: TABLE PHASE =====", flush=True)
    built = _build_phase(csv_path, out_dir)

    mins = (time.time() - started) / 60.0
    print(f"\n===== run_eval DONE in {mins:.0f} min =====")
    if built:
        print(f"Tables: {out_dir}/ablation_table.md and {out_dir}/eval_per_scenario.md")
        print(f"CSV:    {csv_path}")
    else:
        print("No tables yet (runs still confounded/incomplete). Re-launch to "
              "retry confounded cells, or run with --parse-only once more land.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
