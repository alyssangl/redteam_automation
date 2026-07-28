"""
run_matrix.py — the ablation run harness (docs/plans/eval_benchmark.md §5.2).

For each (scenario x variant x repeat) cell it:
  1. restarts msfrpcd to a clean state (lab hygiene),
  2. sets the ablation env flags for that variant,
  3. runs the orchestrator (or the naive baseline for V6),
  4. saves the run's checkpoint + full timestamped log under logs/eval/ as
     `<scenario>__<variant>__r<rep>.{json,log}` — the exact pairing parse_eval
     expects.

Each cell runs as an ISOLATED SUBPROCESS (`--single`) so a hang or crash in one
cell can't take down the overnight matrix, and each cell gets a clean env + a
hard per-cell timeout. The parent just orchestrates.

Usage:
  # dry run — print the plan, touch nothing (no lab needed):
  python experiments/run_matrix.py --dry-run

  # the three killer ablations on the recovery scenarios, N=5:
  python experiments/run_matrix.py \
      --scenarios flaw_privesc flaw_persistence goal_only \
      --variants v0_full v1_noreplan v3_noground v4_nodeterm \
      --reps 5

  # one cell (what the parent spawns; also handy for debugging):
  python experiments/run_matrix.py --single \
      --scenario flaw_persistence --variant v0_full --rep 0
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

EVAL_DIR = ROOT / "logs" / "eval"
LOGS_DIR = ROOT / "logs"

DEFAULT_TARGET = "192.168.34.7"
DEFAULT_ATTACKER = os.getenv("LHOST", "192.168.34.6")

# Per-cell wall-clock ceiling. A wedged msfrpcd shows a 120s-per-command
# signature; a healthy full-chain run is ~15-25 min, so 40 min is a generous cap
# that still catches a truly stuck cell.
DEFAULT_TIMEOUT = 40 * 60

# --- The variant matrix (rows of the ablation table) -----------------------
# Each variant = orchestrator flags (explore/judge) + ablation env vars. The env
# defaults are ON, so V0 sets nothing. V6 is the naive single-loop baseline.
VARIANTS: dict[str, dict] = {
    "v0_full":     {"explore": True,  "judge": True,  "env": {}},
    "v1_noreplan": {"explore": True,  "judge": True,  "env": {"EVAL_ENABLE_REPLAN": "0"}},
    "v2_nojudge":  {"explore": True,  "judge": False, "env": {}},
    "v3_noground": {"explore": True,  "judge": True,  "env": {"EVAL_GROUND_SUCCESS": "0"}},
    "v4_nodeterm": {"explore": True,  "judge": True,  "env": {"EVAL_DETERMINISTIC_TECHNIQUE": "0"}},
    "v5_norag":    {"explore": True,  "judge": True,  "env": {"EVAL_ENABLE_RAG": "0"}},
    "v6_naive":    {"baseline": True},
}

# The recovery benchmark = the flaw_* graphs + the full-chain goal_only. These
# already exist as examples/*_graph.py (see ui.registry).
DEFAULT_SCENARIOS = [
    "goal_only",
    "flaw_recon", "flaw_initial_access", "flaw_privesc",
    "flaw_persistence", "flaw_impact",
]


def _run_tag(scenario: str, variant: str, rep: int) -> str:
    return f"{scenario}__{variant}__r{rep}"


# =============================================================================
# Single-cell execution (runs inside an isolated subprocess)
# =============================================================================

def _run_single(scenario: str, variant: str, rep: int,
                target: str, attacker: str) -> int:
    """Execute ONE matrix cell in-process. Writes the eval log + checkpoint."""
    if variant not in VARIANTS:
        print(f"unknown variant: {variant}", file=sys.stderr)
        return 2
    spec = VARIANTS[variant]
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    tag = _run_tag(scenario, variant, rep)
    checkpoint = EVAL_DIR / f"{tag}.json"
    eval_log = EVAL_DIR / f"{tag}.log"

    # The env flags are already set by the parent before spawning us; log them.
    from core_agents import eval_flags
    print(f"[cell] {tag}  target={target}  disabled={eval_flags.active_ablations()}",
          flush=True)

    started = time.time()

    if spec.get("baseline"):
        from experiments.baseline_agent import run_baseline
        run_baseline(scenario, target=target, attacker=attacker,
                     checkpoint_path=str(checkpoint), log_path=str(eval_log))
        return 0

    # Orchestrator variant.
    from ui.registry import resolve_builder
    from core_agents.orchestrator import run_graph

    builder = resolve_builder(scenario)
    graph = builder(target_ip=target, attacker_ip=attacker)
    graph.save(str(checkpoint))

    run_graph(
        graph,
        checkpoint_path=str(checkpoint),
        explore=spec["explore"],
        use_judge=spec["judge"],
    )

    # run_graph wrote its own timestamped file log to logs/<graph.name>_<ts>.log.
    # Copy the newest one created during this cell into logs/eval/<tag>.log so
    # parse_eval finds the log next to the checkpoint.
    _copy_run_log(graph.name, started, eval_log)
    return 0


def _copy_run_log(graph_name: str, since: float, dest: Path) -> None:
    candidates = [
        p for p in LOGS_DIR.glob(f"{graph_name}_*.log")
        if p.stat().st_mtime >= since - 2
    ]
    if not candidates:
        print(f"[warn] no run log found for {graph_name} to copy", file=sys.stderr)
        return
    newest = max(candidates, key=lambda p: p.stat().st_mtime)
    shutil.copyfile(newest, dest)


# =============================================================================
# Matrix orchestration (the parent process)
# =============================================================================

def _restart_msf() -> None:
    """Best-effort clean msfrpcd before a cell. Non-fatal if the lab is absent."""
    try:
        subprocess.run(
            [sys.executable, str(ROOT / "experiments" / "restart_msf.py")],
            timeout=90, cwd=str(ROOT),
        )
    except Exception as e:
        print(f"[warn] restart_msf failed (continuing): {e}", file=sys.stderr)


def _preserve_timeout_log(tag: str, since: float) -> None:
    """On a cell timeout the subprocess is killed before it can copy its own log,
    so the eval pair goes missing and the signal is lost. Copy the partial run
    log (newest logs/*.log touched during the cell) into logs/eval/<tag>.log and
    stamp a CONFOUNDED marker so parse_eval can EXCLUDE it (a wedged-console
    timeout is a lab confounder to discard/retry, NOT full-system non-termination
    — see eval_benchmark.md §7). skip-done still sees no EXECUTION COMPLETE, so a
    relaunch naturally retries the cell."""
    dest = EVAL_DIR / f"{tag}.log"
    candidates = [p for p in LOGS_DIR.glob("*.log") if p.stat().st_mtime >= since - 2]
    body = ""
    if candidates:
        newest = max(candidates, key=lambda p: p.stat().st_mtime)
        try:
            body = newest.read_text(encoding="utf-8", errors="replace")
        except Exception:
            body = ""
    marker = ("\n[HARNESS] CELL TIMEOUT / CONFOUNDED — the run exceeded the "
              "per-cell wall-clock cap (likely a wedged msfrpcd/console). Excluded "
              "from metrics; retried on relaunch.\n")
    dest.write_text(body + marker, encoding="utf-8")


def _spawn_cell(scenario: str, variant: str, rep: int,
                target: str, attacker: str, timeout: int) -> str:
    """Run one cell as an isolated subprocess. Returns a status string."""
    env = dict(os.environ)
    env.update(VARIANTS[variant].get("env", {}))
    cmd = [
        sys.executable, str(Path(__file__)), "--single",
        "--scenario", scenario, "--variant", variant, "--rep", str(rep),
        "--target", target, "--attacker", attacker,
    ]
    tag = _run_tag(scenario, variant, rep)
    print(f"\n=== CELL {tag} (timeout {timeout}s) ===", flush=True)
    started = time.time()
    try:
        r = subprocess.run(cmd, env=env, timeout=timeout, cwd=str(ROOT))
        return "ok" if r.returncode == 0 else f"exit{r.returncode}"
    except subprocess.TimeoutExpired:
        print(f"[timeout] {tag} exceeded {timeout}s — preserving partial log as "
              f"CONFOUNDED (excluded, retried on relaunch)", file=sys.stderr)
        _preserve_timeout_log(tag, started)
        return "timeout"


def _cell_done(scenario: str, variant: str, rep: int) -> bool:
    """A cell counts as done only if its eval log reached EXECUTION COMPLETE AND
    the run is NOT confounded — so resume skips valid results but RETRIES confounded
    ones until a clean run lands.

    Subtlety: a recon/root-node failure (flaky target) still prints EXECUTION
    COMPLETE at 0%, so an EXECUTION-COMPLETE check alone would wrongly treat it as
    done and never retry it. We exclude the same confounders parse_eval excludes
    (harness timeout, wedged console, recon/root failure) using its markers."""
    from experiments import parse_eval as _pe
    log = EVAL_DIR / f"{_run_tag(scenario, variant, rep)}.log"
    if not log.exists():
        return False
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    if "[Orchestrator] EXECUTION COMPLETE" not in text:
        return False
    if (_pe._CONFOUNDED in text or _pe._WEDGE_SENTINEL in text
            or _pe._RECON_FAILED_LINE.search(text)):
        return False  # confounded -> not a valid result -> retry on resume
    return True


def _run_matrix(scenarios, variants, reps, target, attacker,
                timeout, restart, skip_done=True) -> None:
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    total = len(scenarios) * len(variants) * reps
    done = 0
    results: dict[str, str] = {}
    for scenario in scenarios:
        for variant in variants:
            for rep in range(reps):
                done += 1
                tag = _run_tag(scenario, variant, rep)
                if skip_done and _cell_done(scenario, variant, rep):
                    print(f"\n########## [{done}/{total}] {tag} — SKIP (already complete) ##########",
                          flush=True)
                    results[tag] = "skip"
                    continue
                print(f"\n########## [{done}/{total}] {tag} ##########", flush=True)
                if restart:
                    _restart_msf()
                status = _spawn_cell(scenario, variant, rep,
                                     target, attacker, timeout)
                results[tag] = status
    print("\n================ MATRIX COMPLETE ================")
    for tag, status in results.items():
        print(f"  {status:8s} {tag}")
    print(f"\nNext: python experiments/parse_eval.py --eval-dir logs/eval "
          f"-o eval_results.csv")


def _dry_run(scenarios, variants, reps) -> None:
    total = len(scenarios) * len(variants) * reps
    print(f"DRY RUN — {total} cells "
          f"({len(scenarios)} scenarios x {len(variants)} variants x {reps} reps)\n")
    for scenario in scenarios:
        for variant in variants:
            spec = VARIANTS[variant]
            if spec.get("baseline"):
                detail = "naive single-loop baseline"
            else:
                env = spec.get("env") or {}
                detail = (f"explore={spec['explore']} judge={spec['judge']} "
                          f"env={env or '(defaults)'}")
            print(f"  {scenario:22s} {variant:12s} x{reps}  ->  {detail}")
    print("\n(no lab touched; drop --dry-run to execute)")


def main() -> int:
    # Survive non-ascii (em-dash, ✓) on legacy Windows consoles (cp932/cp1252).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(description="Ablation run harness.")
    ap.add_argument("--single", action="store_true",
                    help="run ONE cell in-process (used by the parent; also for debugging)")
    ap.add_argument("--scenario", help="single-cell scenario key")
    ap.add_argument("--variant", help="single-cell variant key")
    ap.add_argument("--rep", type=int, default=0, help="single-cell repeat index")

    ap.add_argument("--scenarios", nargs="+", default=DEFAULT_SCENARIOS)
    ap.add_argument("--variants", nargs="+", default=list(VARIANTS.keys()))
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--target", default=DEFAULT_TARGET)
    ap.add_argument("--attacker", default=DEFAULT_ATTACKER)
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help="per-cell wall-clock ceiling (seconds)")
    ap.add_argument("--no-restart", action="store_true",
                    help="skip restart_msf before each cell")
    ap.add_argument("--no-skip-done", action="store_true",
                    help="re-run cells even if a completed log already exists "
                         "(default: skip completed cells so the matrix is resumable)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan and exit (no lab needed)")
    args = ap.parse_args()

    unknown = [v for v in args.variants if v not in VARIANTS]
    if unknown:
        print(f"unknown variant(s): {unknown}\n known: {list(VARIANTS)}", file=sys.stderr)
        return 2

    if args.single:
        if not (args.scenario and args.variant):
            print("--single needs --scenario and --variant", file=sys.stderr)
            return 2
        return _run_single(args.scenario, args.variant, args.rep,
                           args.target, args.attacker)

    if args.dry_run:
        _dry_run(args.scenarios, args.variants, args.reps)
        return 0

    _run_matrix(args.scenarios, args.variants, args.reps,
                args.target, args.attacker, args.timeout,
                restart=not args.no_restart,
                skip_done=not args.no_skip_done)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
