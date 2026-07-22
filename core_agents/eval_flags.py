"""
eval_flags.py — ablation toggles for the evaluation study.

The paper's spine is an ablation table (docs/plans/eval_benchmark.md): run the
full system, then knock out one layer at a time and watch a metric collapse.
Rather than thread four bool params through every stage/tool signature, each
layer reads its toggle here. The run harness (experiments/run_matrix.py) sets
the env vars per run; everything defaults to ON (full system) so normal runs and
the offline suite are unaffected.

Toggles (all default True = full system):
  EVAL_ENABLE_REPLAN          V1: L3 graph mutation (_replan_from). Off -> the
                              replanner is a no-op; a stuck/failed node just
                              backtracks. Recovery should collapse.
  EVAL_GROUND_SUCCESS         V3: deterministic ground-truth re-check in the
                              stage critics. Off -> a critic PASS is accepted on
                              the LLM's say-so. False-success should explode.
  EVAL_DETERMINISTIC_TECHNIQUE V4: technique lock + feasibility precheck +
                              replanner tried-tracking. Off -> the subagent may
                              free-select and repeat techniques. Loops should rise.
  EVAL_ENABLE_RAG             V5: query_knowledge_base. Off -> returns empty.
"""

from __future__ import annotations

import os

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _flag(name: str, default: bool = True) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    v = v.strip().lower()
    if v in _FALSE:
        return False
    if v in _TRUE:
        return True
    return default


def replan_enabled() -> bool:
    return _flag("EVAL_ENABLE_REPLAN", True)


def grounding_enabled() -> bool:
    return _flag("EVAL_GROUND_SUCCESS", True)


def deterministic_technique_enabled() -> bool:
    return _flag("EVAL_DETERMINISTIC_TECHNIQUE", True)


def rag_enabled() -> bool:
    return _flag("EVAL_ENABLE_RAG", True)


def active_ablations() -> list[str]:
    """Human-readable list of the layers currently DISABLED (for run logging)."""
    off = []
    if not replan_enabled():
        off.append("replan")
    if not grounding_enabled():
        off.append("grounding")
    if not deterministic_technique_enabled():
        off.append("determinism")
    if not rag_enabled():
        off.append("rag")
    return off
