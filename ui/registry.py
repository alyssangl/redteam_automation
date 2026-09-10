"""Discover the attack-graph builders in examples/ without importing anything heavy.

The cockpit process only ever calls `list_graph_keys()` (pure filename scan — no
imports, so the TUI never drags in orchestrator/langchain). The headless run
subprocess calls `resolve_builder()` to turn a key back into its build_* function.

Key convention: `examples/<key>_graph.py` -> key. e.g. goal_only_graph.py -> "goal_only".
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path

_EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def list_graph_keys() -> list[str]:
    """Sorted graph keys, derived from filenames only (no import side effects)."""
    return sorted(
        f.stem[: -len("_graph")]
        for f in _EXAMPLES_DIR.glob("*_graph.py")
        if f.stem.endswith("_graph")
    )


def resolve_builder(key: str):
    """Import examples.<key>_graph and return its build_* function.

    Only called inside the headless subprocess, so importing the example (which
    pulls core_agents.attack_graph — stdlib-only) is fine here.
    """
    module_name = f"examples.{key}_graph"
    module = importlib.import_module(module_name)
    for name, obj in vars(module).items():
        if (
            name.startswith("build_")
            and inspect.isfunction(obj)
            and obj.__module__ == module.__name__
        ):
            return obj
    raise ValueError(f"No build_* function found in {module_name}")
