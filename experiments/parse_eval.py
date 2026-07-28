"""
parse_eval.py — deterministic metrics extractor for the ablation study.

Turns each finished run (one orchestrator .log + its checkpoint .json) into a
single CSV row of the metrics defined in docs/plans/eval_benchmark.md §3. The
whole point is REPRODUCIBLE numbers: everything here is computed programmatically
from the artifacts we already emit — never eyeballed, never from the agent's own
success claim (false-success is re-derived from independent ground truth in the
node findings).

Metric columns (per run):
  scenario, variant, rep        — run identity (from filename or graph name)
  completed                     — reached "[Orchestrator] EXECUTION COMPLETE"
  success_rate                  — graph success rate (0..1) from the summary
  grounded_success              — objective node reached success WITH grounding
                                  evidence (session opened / uid=0 / proof marker)
  false_success                 — >=1 node claims success but has NO grounding
                                  evidence (the money metric for the grounding claim)
  false_success_nodes           — which nodes those were (";"-joined)
  recovered                     — flaw_* only: objective met via a replanner-grown
                                  node despite the injected failure
  replan_capped                 — hit the replan budget ("Replan budget exhausted")
  non_termination               — never reached COMPLETE, or capped without success
  replan_edits                  — NEW EDGE + NEW NODE + GROW TECHNIQUE count
  judge_continue/adapt/escalate — [Judge] decision counts
  wall_secs                     — last log timestamp minus first (HH:MM:SS)

Usage:
  python experiments/parse_eval.py --eval-dir logs/eval -o eval_results.csv
  python experiments/parse_eval.py --pair <run.log> <checkpoint.json>   # one-off
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Optional

# --- log markers (kept in one place; grep the codebase if the orchestrator
#     rewords them) --------------------------------------------------------
_COMPLETE = "[Orchestrator] EXECUTION COMPLETE"
# A cell is confounded (lab artifact, excluded from metrics) if the harness timed
# it out OR the msf console wedged mid-run (the sentinel rides into the log via
# the orchestrator's output-preview line) — either way it's not real system behavior.
_CONFOUNDED = "[HARNESS] CELL TIMEOUT / CONFOUNDED"
_WEDGE_SENTINEL = "[MSF_CONSOLE_WEDGED]"
# A recon/root-node FAILURE is a lab artifact too, not real system behavior: recon
# is the graph root, so when the flaky target drops nmap packets recon fails and the
# walker skips the ENTIRE downstream chain -> a spurious 0%. Treat it exactly like
# the msf-wedge confounder (excluded + resume-retried). Scope is PRECISE: only the
# recon/root node failing — a run that recons fine and legitimately dead-ends later
# (v1_noreplan, a privesc that can't escalate) is REAL data and stays counted.
_RECON_FAILED_LINE = re.compile(r"[✗x]\s*recon:\s*failed", re.IGNORECASE)
_SUCCESS_RATE = re.compile(r"Success rate:\s*(\d+)%")
_REPLAN_CAP = "Replan budget exhausted"
_REPLAN_EDIT = re.compile(r"\[Replanner\] (NEW EDGE|NEW NODE|GROW TECHNIQUE)")
_JUDGE = re.compile(r"\[Judge\] \w+:\s*(continue|adapt|escalate)\b")
_TS = re.compile(r"^(\d{2}):(\d{2}):(\d{2})\b")

# Priority of tactic/agent_type when picking the run's OBJECTIVE node. The
# objective is the deepest kill-chain stage the scenario intends to reach.
_OBJECTIVE_PRIORITY = ["impact", "persistence", "privesc", "exploit",
                       "initial_access", "recon", "discovery"]


# =============================================================================
# Grounding — the independent ground-truth check (NOT the agent's own verdict)
# =============================================================================

def _grounded(node: dict) -> bool:
    """Does this SUCCEEDED node carry real proof it worked, per its stage?

    Deterministic re-derivation from the node's findings — this is what
    separates a grounded success from a false success (claimed, no evidence).
    """
    f = node.get("findings") or {}
    atype = (node.get("agent_type") or "").lower()
    summary = (node.get("summary") or "").lower()

    if atype == "recon":
        return bool(f.get("ports") or f.get("raw_nmap_output"))
    if atype in ("exploit", "initial_access"):
        # Ground truth = a real session was opened.
        return bool(f.get("session_id")) or "session" in summary and "opened" in summary
    if atype == "privesc":
        # Ground truth = escalated session + root level.
        lvl = str(f.get("new_level") or f.get("access_level") or "").lower()
        return bool(f.get("session_id")) and (lvl in ("root", "") ) or "uid=0" in summary
    if atype == "persistence":
        # Ground truth = a concrete method landed and was NOT exhausted/unverified.
        if f.get("technique_exhausted") or f.get("direct_attempt_failed") and not f.get("session_id"):
            return False
        return bool(f.get("method")) and bool(f.get("success"))
    if atype in ("impact", "session", "discovery"):
        # Ground truth = real command output / a read-back proof marker.
        return bool(f.get("output")) or "pwned" in summary or bool(f.get("proof"))
    # Unknown stage: fall back to any concrete evidence at all.
    return bool(f.get("output") or f.get("session_id") or f.get("ports"))


def _objective_node(nodes: dict) -> Optional[dict]:
    """Pick the run's objective node = the deepest intended kill-chain stage."""
    by_type: dict[str, dict] = {}
    for n in nodes.values():
        atype = (n.get("agent_type") or "").lower()
        # keep the LAST node of each type (grown recovery nodes come later)
        by_type[atype] = n
    for atype in _OBJECTIVE_PRIORITY:
        if atype in by_type:
            return by_type[atype]
    return next(iter(nodes.values()), None)


def _root_node_ids(cp: dict) -> set[str]:
    """Graph root(s) = node ids that are never the TARGET of any edge.

    Recon is the entry node in every eval scenario; a root failure cascades to
    every downstream node (they end up `skipped`). We derive it structurally from
    the edge list so it holds even if the root is renamed away from "recon".
    """
    nodes = cp.get("nodes") or {}
    if not nodes:
        return set()
    targets = {e.get("target") for e in (cp.get("edges") or []) if e.get("target")}
    return {nid for nid in nodes if nid not in targets}


def _recon_or_root_failed(cp: dict) -> bool:
    """True iff the recon stage OR the graph root node ended `status == 'failed'`.

    This is the confounder signal: a root/recon failure is (in this lab) a flaky-
    target artifact that zeroes the whole chain. Deliberately narrow — it does NOT
    fire for a downstream node failing, so genuine later dead-ends stay counted.
    """
    nodes = cp.get("nodes") or {}
    if not nodes:
        return False
    root_ids = _root_node_ids(cp)
    for nid, n in nodes.items():
        if (n.get("status") or "").lower() != "failed":
            continue
        if (n.get("agent_type") or "").lower() == "recon":
            return True
        if nid in root_ids:
            return True
    return False


# =============================================================================
# Log parsing
# =============================================================================

def _parse_log(text: str) -> dict:
    completed = _COMPLETE in text
    # confounded from the log: harness timeout, msf-console wedge, OR the summary
    # line showing the recon/root node failed (the checkpoint gives the primary,
    # structural signal — this log line is a resilient fallback).
    confounded = (
        (_CONFOUNDED in text)
        or (_WEDGE_SENTINEL in text)
        or bool(_RECON_FAILED_LINE.search(text))
    )
    replan_capped = _REPLAN_CAP in text
    replan_edits = len(_REPLAN_EDIT.findall(text))
    judge = {"continue": 0, "adapt": 0, "escalate": 0}
    for m in _JUDGE.finditer(text):
        judge[m.group(1)] += 1

    sr = _SUCCESS_RATE.search(text)
    success_rate = int(sr.group(1)) / 100.0 if sr else None

    # wall time from first/last HH:MM:SS timestamp
    first = last = None
    for line in text.splitlines():
        m = _TS.match(line)
        if not m:
            continue
        secs = int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
        if first is None:
            first = secs
        last = secs
    wall = None
    if first is not None and last is not None:
        wall = last - first
        if wall < 0:  # crossed midnight
            wall += 86400

    return {
        "completed": completed,
        "confounded": confounded,
        "replan_capped": replan_capped,
        "replan_edits": replan_edits,
        "judge_continue": judge["continue"],
        "judge_adapt": judge["adapt"],
        "judge_escalate": judge["escalate"],
        "log_success_rate": success_rate,
        "wall_secs": wall,
    }


# =============================================================================
# Checkpoint parsing
# =============================================================================

def _parse_checkpoint(cp: dict) -> dict:
    nodes = cp.get("nodes") or {}
    total = len(nodes) or 1
    succeeded = [n for n in nodes.values() if n.get("status") == "success"]

    # false success: a node claims success but has no grounding evidence
    false_nodes = [n.get("id", "?") for n in succeeded if not _grounded(n)]

    obj = _objective_node(nodes)
    obj_success = bool(obj and obj.get("status") == "success" and _grounded(obj))

    # recovery: objective met AND a replanner-grown node carried it
    grown_success = any(
        n.get("status") == "success" and "replanner_generated" in (n.get("tags") or [])
        for n in nodes.values()
    )

    return {
        "cp_success_rate": len(succeeded) / total,
        "grounded_success": obj_success,
        "objective_node": obj.get("id") if obj else "",
        "false_success": bool(false_nodes),
        "false_success_nodes": ";".join(false_nodes),
        "grown_node_success": grown_success,
        "graph_status": cp.get("status", ""),
        # Primary (structural) confounder signal: recon/root node failed -> the
        # whole chain was skipped, a lab artifact. OR'd into `confounded` in
        # evaluate_run alongside the log-derived signal.
        "recon_confounded": _recon_or_root_failed(cp),
    }


# =============================================================================
# Per-run assembly
# =============================================================================

def _identity(log_path: Path, cp: dict) -> tuple[str, str, str]:
    """(scenario, variant, rep) from a `scenario__variant__rN` filename, else
    fall back to the graph name / defaults."""
    stem = log_path.stem
    parts = stem.split("__")
    if len(parts) >= 3:
        scenario, variant = parts[0], parts[1]
        rep = re.sub(r"[^0-9]", "", parts[2]) or "0"
        return scenario, variant, rep
    name = cp.get("name", stem)
    # strip trailing _<ip>_<ts> noise
    scenario = re.sub(r"_\d+\.\d+\.\d+\.\d+.*$", "", name) or name
    return scenario, "v0_full", "0"


def evaluate_run(log_path: Path, cp_path: Path) -> dict:
    text = log_path.read_text(encoding="utf-8", errors="replace")
    try:
        cp = json.loads(cp_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        # A confounded/killed cell can leave a truncated checkpoint — still emit a
        # row (it will carry confounded=True and be excluded downstream).
        cp = {}

    scenario, variant, rep = _identity(log_path, cp)
    row = {"scenario": scenario, "variant": variant, "rep": rep,
           "log": log_path.name}
    row.update(_parse_log(text))
    row.update(_parse_checkpoint(cp))

    # Fold the structural recon/root-failure signal into `confounded` (the log
    # parser already OR'd in its own recon-fail line). Keeping both makes the
    # exclusion robust to a truncated checkpoint OR a reworded summary line.
    row["confounded"] = bool(row.get("confounded")) or bool(row.pop("recon_confounded", False))

    # derived: recovery is only meaningful on flaw_* scenarios
    is_flaw = scenario.startswith("flaw")
    row["recovered"] = bool(
        is_flaw and row["grounded_success"] and row["grown_node_success"]
    )
    # non-termination: never completed, or capped the replan budget without
    # actually reaching the objective.
    row["non_termination"] = bool(
        (not row["completed"]) or (row["replan_capped"] and not row["grounded_success"])
    )
    # prefer the log's reported rate; fall back to the checkpoint count
    row["success_rate"] = (
        row.pop("log_success_rate") if row.get("log_success_rate") is not None
        else row["cp_success_rate"]
    )
    return row


# column order for the CSV
_COLUMNS = [
    "scenario", "variant", "rep", "log",
    "confounded",
    "completed", "success_rate", "grounded_success", "objective_node",
    "false_success", "false_success_nodes", "recovered",
    "replan_capped", "non_termination", "replan_edits",
    "judge_continue", "judge_adapt", "judge_escalate",
    "wall_secs", "graph_status", "cp_success_rate", "grown_node_success",
]


def _pair_up(eval_dir: Path) -> list[tuple[Path, Path]]:
    """Match each <name>.log to its sibling <name>.json in eval_dir."""
    pairs = []
    for log_path in sorted(eval_dir.glob("*.log")):
        cp_path = log_path.with_suffix(".json")
        if cp_path.exists():
            pairs.append((log_path, cp_path))
        else:
            print(f"  [skip] no checkpoint for {log_path.name}", file=sys.stderr)
    return pairs


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract ablation metrics from runs.")
    ap.add_argument("--eval-dir", default="logs/eval",
                    help="dir of <name>.log + sibling <name>.json run pairs")
    ap.add_argument("--pair", nargs=2, metavar=("LOG", "CHECKPOINT"),
                    help="evaluate a single log+checkpoint pair and print its row")
    ap.add_argument("-o", "--out", default=None, help="write CSV to this path")
    args = ap.parse_args()

    if args.pair:
        row = evaluate_run(Path(args.pair[0]), Path(args.pair[1]))
        w = csv.DictWriter(sys.stdout, fieldnames=_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerow(row)
        return 0

    eval_dir = Path(args.eval_dir)
    if not eval_dir.exists():
        print(f"eval dir not found: {eval_dir}", file=sys.stderr)
        return 1
    pairs = _pair_up(eval_dir)
    if not pairs:
        print(f"no run pairs found in {eval_dir}", file=sys.stderr)
        return 1

    rows = []
    for log_path, cp_path in pairs:
        try:
            rows.append(evaluate_run(log_path, cp_path))
        except Exception as e:  # one bad run must not kill the batch
            print(f"  [error] {log_path.name}: {e}", file=sys.stderr)

    out = Path(args.out) if args.out else None
    fh = out.open("w", newline="", encoding="utf-8") if out else sys.stdout
    try:
        w = csv.DictWriter(fh, fieldnames=_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    finally:
        if out:
            fh.close()
    print(f"parsed {len(rows)} run(s)"
          + (f" -> {out}" if out else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
