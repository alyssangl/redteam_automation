"""Headless entrypoint the cockpit spawns as a subprocess.

Builds the chosen graph, writes an initial checkpoint (so the UI can render the
plan instantly), then walks it with run_graph. The orchestrator's console logging
goes to stderr; we merge it into the cockpit's decision ticker. Sentinel lines
([[UI_META]] / [[UI_DONE]] / [[UI_ERROR]]) let the cockpit track lifecycle.

Usage:
    python ui/headless_run.py --graph goal_only --target 192.168.34.7 \
        --attacker 192.168.34.6 --checkpoint graphs/_ui_goal_only.json --explore
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser(description="Headless orchestrator run for the cockpit.")
    ap.add_argument("--graph", required=True, help="graph key (see ui.registry.list_graph_keys)")
    ap.add_argument("--target", default="192.168.34.7")
    ap.add_argument("--attacker", default="192.168.34.6")
    ap.add_argument("--checkpoint", required=True, help="where to write live graph state (JSON)")
    ap.add_argument("--explore", action="store_true", help="enable subagent fallback + replanner")
    ap.add_argument("--judge", dest="judge", action="store_true")
    ap.add_argument("--no-judge", dest="judge", action="store_false")
    ap.set_defaults(judge=True)
    args = ap.parse_args()

    # Stream immediately, and survive non-ascii banners on Windows consoles.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", line_buffering=True)
        except Exception:
            pass

    from ui.registry import resolve_builder

    builder = resolve_builder(args.graph)
    graph = builder(target_ip=args.target, attacker_ip=args.attacker)

    # Initial snapshot — the cockpit polls this file, so save before we start
    # so the plan is visible the instant the run launches.
    Path(args.checkpoint).parent.mkdir(parents=True, exist_ok=True)
    graph.save(args.checkpoint)
    print(
        f"[[UI_META]] name={graph.name} nodes={len(graph.nodes)} edges={len(graph.edges)}",
        flush=True,
    )

    from core_agents.orchestrator import run_graph

    try:
        run_graph(
            graph,
            checkpoint_path=args.checkpoint,
            explore=args.explore,
            use_judge=args.judge,
        )
        print("[[UI_DONE]]", flush=True)
        return 0
    except KeyboardInterrupt:
        print("[[UI_ERROR]] interrupted", flush=True)
        return 130
    except Exception as exc:  # noqa: BLE001 — surface everything to the ticker
        traceback.print_exc()
        print(f"[[UI_ERROR]] {exc}", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
