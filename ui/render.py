"""Render a checkpoint-JSON graph dict into a Rich renderable for the cockpit.

Works purely off the serialized dict (AttackGraph.to_dict), so the cockpit never
imports core_agents. Nodes are listed in insertion order — replanner-added nodes
naturally appear at the bottom as the graph grows, which is exactly the mutation
you want to watch.
"""

from __future__ import annotations

from rich.console import Group
from rich.text import Text

# status -> (glyph, color) — mirrors AttackGraph.summary()'s icon set
_GLYPH = {
    "pending": ("○", "grey62"),
    "running": ("▶", "yellow"),
    "success": ("✓", "green"),
    "failed": ("✗", "red"),
    "skipped": ("⊘", "grey42"),
    "blocked": ("⊗", "magenta"),
}


def _truncate(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _is_replanner_node(node: dict) -> bool:
    blob = " ".join(str(t) for t in (node.get("tags") or []))
    blob += " " + " ".join(str(k) for k in (node.get("metadata") or {}))
    blob = blob.lower()
    return "replan" in blob or "generated" in blob


def render_graph(data: dict | None) -> Group:
    if not data:
        return Group(Text("waiting for run to start…", style="grey50"))

    nodes: dict = data.get("nodes", {})
    edges: list = data.get("edges", [])

    # header ------------------------------------------------------------------
    total = len(nodes)
    succeeded = sum(1 for n in nodes.values() if n.get("status") == "success")
    failed = sum(1 for n in nodes.values() if n.get("status") == "failed")
    rate = (succeeded / total) if total else 0.0

    head = Text()
    head.append(data.get("name", "?"), style="bold white")
    head.append(f"  [{data.get('status', '')}]\n", style="cyan")
    obj = data.get("objective", "")
    if obj:
        head.append("objective: ", style="grey50")
        head.append(_truncate(obj, 80) + "\n", style="white")
    head.append(
        f"target {data.get('target_ip', '')}   "
        f"nodes {total}  edges {len(edges)}   ",
        style="grey50",
    )
    head.append(f"✓{succeeded} ", style="green")
    head.append(f"✗{failed} ", style="red")
    head.append(f"({rate:.0%})\n", style="grey50")

    # outgoing-edge adjacency
    outgoing: dict[str, list] = {}
    for edge in edges:
        outgoing.setdefault(edge.get("source"), []).append(edge)

    # body --------------------------------------------------------------------
    body = Text()
    for node_id, node in nodes.items():
        status = node.get("status", "pending")
        glyph, color = _GLYPH.get(status, ("?", "white"))

        body.append(f"{glyph} ", style=color)
        body.append(node_id, style=f"bold {color}")
        label = node.get("label", "")
        if label and label != node_id:
            body.append(f"  {label}", style=color)
        module = node.get("module", "")
        if module:
            body.append(f"  ({_truncate(module, 40)})", style="grey42")
        retries = node.get("retries", 0)
        if retries:
            body.append(f"  ↻{retries}", style="yellow")
        if _is_replanner_node(node):
            body.append("  ✚replan", style="bold magenta")
        body.append(f"  [{status}]\n", style=color)

        summary = node.get("summary", "")
        if summary:
            body.append(f"    ↳ {_truncate(summary, 88)}\n", style="grey54")

        for edge in outgoing.get(node_id, []):
            cond = edge.get("condition", "on_success")
            body.append(f"      └▶ {edge.get('target', '')}", style="grey58")
            if cond != "on_success":
                body.append(f"  [{cond}]", style="grey42")
            rationale = edge.get("rationale", "") or edge.get("evidence", "")
            if rationale:
                body.append(f"  {_truncate(rationale, 64)}", style="grey42")
            body.append("\n")

    return Group(head, body)
