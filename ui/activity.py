"""Parse the orchestrator/subagent output stream into a structured activity feed.

The cockpit receives the run subprocess's merged stdout+stderr. That includes two
kinds of lines:
  - orchestrator logger lines (stderr, plain `%(message)s`): [Dispatch], [Judge],
    [Replanner], [Orchestrator], `[<node>] STATUS → ...`, `[<stage>] findings: {json}`.
  - stage subagent prints (stdout, ANSI-colored via print_colored): `[Recon
    Planner]`, `[* Executor]`, `[* Terminal] Executing: <cmd>`, `[* Critic]`,
    `[* Probe] UPGRADE SUCCESS ...`, `[direct] > <cmd>`, `[direct] session(N)> <cmd>`
    — these never reach the .log file, only the live stream.

ActivityParser turns the meaningful subset into clean, grouped, styled lines. One
block per node execution:

    ▶ agent · node   label
      ─ round N
        plan   <what it decided to do>
        run    <the actual command it ran>          ← "what command it's running"
        ⇈ upgraded command_shell → meterpreter 8    ← flow change
        critic PASS/FAIL <verdict>
        ↳ <stage summary>  (session 8, root)        ← "summary of finished stage"
        ✓ success — <result>
      ⚖ judge post_node → continue: <hint>
      ✚ grow technique persistence_cron_job (T1053.003)  ↦ file_drop   ← replanner flow change
      ↩ backtrack to gain_access

Pure functions (str -> list[Text]) so it can be unit-tested against real logs.
"""

from __future__ import annotations

import json
import re

from rich.text import Text

# strip ANSI color codes that print_colored injects on stdout
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# stage/agent -> accent colour for headers
_STAGE_COLOR = {
    "recon": "cyan",
    "exploit": "green",
    "initial_access": "green",
    "privesc": "magenta",
    "persistence": "blue",
    "impact": "red",
    "discovery": "cyan",
}


def strip_ansi(line: str) -> str:
    return _ANSI.sub("", line)


def _color_for(agent: str) -> str:
    return _STAGE_COLOR.get(agent, "white")


def _trunc(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# -- line patterns ------------------------------------------------------------
_RE = {
    "dispatch": re.compile(r"\[Dispatch\] node='(?P<id>[^']+)' label='(?P<label>[^']*)' agent=(?P<agent>\S+)"),
    "status": re.compile(r"\[(?P<node>[\w .-]+)\] STATUS → (?P<status>\w+)(?: \((?P<n>\d+)/(?P<m>\d+)\))?(?:: (?P<reason>.*))?$"),
    "findings": re.compile(r"\[(?P<stage>[\w]+)\] findings: (?P<json>\{.*\})\s*$"),
    "planner": re.compile(r"\[(?P<who>[\w ]*Planner)\]\s*(?P<text>.+)$"),
    "critic": re.compile(r"\[(?P<who>[\w ]*Critic)\]\s*(?P<text>.+)$"),
    "commands": re.compile(r"commands_to_run:\s*(?P<cmds>\[.*\])\s*$"),
    # --- what command it's running (the big gap) ---
    #   [Terminal Tool] Executing: nmap ...   |  [Persistence Terminal] Executing: sleep 70
    "exec_cmd": re.compile(r"\[(?P<who>[\w ]*Terminal(?: Tool)?)\] Executing:\s*(?P<cmd>.+)$"),
    #   [direct] session(18)> echo 'PWNED' > /tmp/pwned...
    "sess_cmd": re.compile(r"\[direct\] session\((?P<sid>\d+)\)>\s*(?P<cmd>.+)$"),
    #   [direct] > run   |   [direct] > exploit   |   [direct] > use exploit/...  (skip `set`/echoes)
    "msf_cmd": re.compile(r"\[direct\] >\s*(?P<cmd>(?:run|exploit|use|sessions)\b.*)$"),
    # --- session lifecycle / flow changes ---
    "session_opened": re.compile(r"(?P<kind>Meterpreter|Command shell) session (?P<sid>\d+) opened", re.I),
    "upgrading": re.compile(r"\[[\w ]*Probe\] Upgrading command_shell (?P<sid>\d+)"),
    "upgrade_ok": re.compile(r"\[[\w ]*Probe\] UPGRADE SUCCESS.*?new meterpreter session (?P<sid>\d+)"),
    # --- judge ---
    "judge": re.compile(r"\[Judge\] (?P<trigger>\w+): (?P<action>continue|adapt|escalate)\s*--\s*(?P<hint>.+)$"),
    "judge_fail": re.compile(r"\[Judge\] LLM call failed"),
    # --- replanner: kicks in + changes the flow ---
    "replan_stuck": re.compile(r"\[Replanner\] Stuck at '(?P<id>[^']+)'"),
    "replan_attempt": re.compile(r"\[Orchestrator\] Replan attempt (?P<n>\d+)/(?P<m>\d+)"),
    "grow": re.compile(r"\[Replanner\] GROW TECHNIQUE:\s*(?P<node>\S+)\s*\((?P<tech>[^)]+)\)(?P<rest>.*)$"),
    "replan_newnode": re.compile(r"\[Replanner\] NEW NODE:\s*(?P<rest>.+)$"),
    "replan_newedge": re.compile(r"\[Replanner\] NEW EDGE:\s*(?P<rest>.+)$"),
    "replan_reject": re.compile(r"\[Replanner\] REJECTED\s*(?P<rest>.+)$"),
    "replan_giveup": re.compile(r"\[Replanner\] (?P<rest>Gave up.*|.*exhausted.*|.*Path exhausted.*)$"),
    "orch_done": re.compile(r"\[Orchestrator\] EXECUTION COMPLETE"),
    "orch_backtrack": re.compile(r"\[Orchestrator\] (?:Backtracking to|Replanner exhausted, backtracking to): (?P<id>.+)$"),
    # inherited-successors detail inside a GROW TECHNIQUE line
    "_inherits": re.compile(r"inherits successors:\s*(?P<inh>\[[^\]]*\])"),
}

_STATUS_STYLE = {
    "success": ("✓", "bold green"),
    "failed": ("✗", "bold red"),
    "retry": ("↻", "yellow"),
    "blocked": ("⊗", "magenta"),
    "skipped": ("⊘", "grey50"),
    # 'running' is intentionally omitted: the "▶ agent · node" header already marks
    # the node start, so echoing "STATUS → running" would just double every node.
}


def _is_status_chatter(text: str) -> bool:
    """A planner/critic 'print' that's just a spinner-style status, not content.

    e.g. 'Designing scan strategy...', 'Selecting technique...', 'Evaluating...',
    'Testing mechanism...', 'Installing mechanism...'. Also bare section headers
    ('Plan:', 'PERSISTENCE PLAN:', 'Strategy:') and RAG-budget notices — they carry
    no decision. Drop them so the feed shows real plans/verdicts, not spinner noise."""
    t = text.strip()
    return (
        t.endswith("...") or t.endswith("…") or t.endswith(":")
        or "rag cap" in t.lower()
    )


class ActivityParser:
    """Stateful line-by-line parser. feed(line) -> list[Text] to append."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._node: str | None = None
        self._agent: str = ""
        self._round: int = 0
        self._last_critic: str = ""   # dedupe repeated verdict prints within a node

    # -- small styled-line helpers -------------------------------------------

    @staticmethod
    def _kv(label: str, label_style: str, value: str, value_style: str) -> Text:
        t = Text()
        t.append(label, style=label_style)
        t.append(value, style=value_style)
        return t

    def feed(self, raw: str) -> list[Text]:
        line = strip_ansi(raw).rstrip()
        if not line:
            return []
        out: list[Text] = []

        # ── node start ──────────────────────────────────────────────────────
        m = _RE["dispatch"].search(line)
        if m:
            node, agent = m["id"], m["agent"]
            if node != self._node:
                self._node, self._agent, self._round = node, agent, 0
                self._last_critic = ""
                color = _color_for(agent)
                head = Text()
                head.append("\n▶ ", style=f"bold {color}")
                head.append(f"{agent} · {node}", style=f"bold {color}")
                label = m["label"]
                if label:
                    head.append(f"  {_trunc(label, 42)}", style="grey58")
                out.append(head)
            return out

        # ── planner: the decision (skip spinner chatter) ────────────────────
        m = _RE["planner"].search(line)
        if m:
            text = m["text"]
            if _is_status_chatter(text):
                return out
            self._round += 1
            color = _color_for(self._agent)
            out.append(self._kv(f"  ─ round {self._round}", color, "", color))
            out.append(self._kv("    plan   ", "grey50", _trunc(text, 84), "grey74"))
            return out

        # ── what command it's running ───────────────────────────────────────
        m = _RE["exec_cmd"].search(line)
        if m:
            out.append(self._kv("    run    ", "grey50", _trunc(m["cmd"], 84), "grey85"))
            return out

        m = _RE["sess_cmd"].search(line)
        if m:
            t = self._kv("    run    ", "grey50", _trunc(m["cmd"], 72), "grey85")
            t.append(f"  (session {m['sid']})", style="grey42")
            out.append(t)
            return out

        m = _RE["msf_cmd"].search(line)
        if m:
            out.append(self._kv("    run    ", "grey50", f"msf: {_trunc(m['cmd'], 78)}", "grey74"))
            return out

        m = _RE["commands"].search(line)
        if m:
            out.append(self._kv("    run    ", "grey50", _trunc(m["cmds"], 84), "grey74"))
            return out

        # ── session lifecycle / flow changes ────────────────────────────────
        m = _RE["upgrade_ok"].search(line)
        if m:
            out.append(Text(f"    ⇈ upgraded command_shell → meterpreter {m['sid']}", style="bold green"))
            return out

        m = _RE["upgrading"].search(line)
        if m:
            out.append(Text(f"    ⇈ upgrading shell {m['sid']} → meterpreter…", style="grey58"))
            return out

        m = _RE["session_opened"].search(line)
        if m:
            out.append(Text(f"    ◆ {m['kind'].lower()} session {m['sid']} opened", style="green"))
            return out

        # ── critic verdict (dedupe repeats, drop chatter) ───────────────────
        m = _RE["critic"].search(line)
        if m:
            text = m["text"].strip()
            if _is_status_chatter(text):
                return out
            up = text.upper()
            verdict = "PASS" if "PASS" in up else ("FAIL" if "FAIL" in up else "")
            if verdict and verdict == self._last_critic:
                return out          # already showed this node's verdict
            if verdict:
                self._last_critic = verdict
            style = "green" if verdict == "PASS" else ("red" if verdict == "FAIL" else "grey74")
            out.append(self._kv("    critic ", "grey50", _trunc(text, 80), style))
            return out

        # ── stage summary (findings) ────────────────────────────────────────
        m = _RE["findings"].search(line)
        if m:
            summary = ""
            try:
                data = json.loads(m["json"])
                summary = data.get("summary", "")
                extra = []
                if data.get("session_id"):
                    extra.append(f"session {data['session_id']}")
                if data.get("session_type"):
                    extra.append(str(data["session_type"]))
                if data.get("access_level"):
                    extra.append(str(data["access_level"]))
                if extra:
                    summary = f"{summary}  ({', '.join(extra)})"
            except (json.JSONDecodeError, TypeError):
                summary = ""
            if summary:
                out.append(self._kv("    ↳ ", "grey50", _trunc(summary, 88), "grey82"))
            return out

        # ── node result ─────────────────────────────────────────────────────
        m = _RE["status"].search(line)
        if m:
            status = m["status"]
            if status in _STATUS_STYLE:
                glyph, style = _STATUS_STYLE[status]
                t = Text()
                t.append(f"    {glyph} {status}", style=style)
                if m["n"] and m["m"]:
                    t.append(f" {m['n']}/{m['m']}", style="grey50")
                if m["reason"]:
                    t.append(f" — {_trunc(m['reason'], 72)}", style="grey58")
                out.append(t)
            return out

        # ── judge ───────────────────────────────────────────────────────────
        m = _RE["judge"].search(line)
        if m:
            action = m["action"]
            style = {"continue": "grey62", "adapt": "yellow", "escalate": "bold magenta"}.get(action, "cyan")
            t = Text()
            t.append("  ⚖ judge ", style="cyan")
            t.append(f"{m['trigger']} → {action}", style=style)
            t.append(f": {_trunc(m['hint'], 60)}", style="grey58")
            out.append(t)
            return out

        if _RE["judge_fail"].search(line):
            out.append(Text("  ⚖ judge unavailable (LLM error)", style="grey50"))
            return out

        # ── replanner: kicks in + changes the flow ──────────────────────────
        m = _RE["grow"].search(line)
        if m:
            t = Text()
            t.append("  ✚ grow technique ", style="bold green")
            t.append(m["node"], style="bold green")
            t.append(f"  ({_trunc(m['tech'], 40)})", style="grey62")
            inh = _RE["_inherits"].search(m["rest"] or "")
            if inh:
                t.append(f"  ↦ inherits {inh['inh']}", style="cyan")
            out.append(t)
            return out

        m = _RE["replan_attempt"].search(line)
        if m:
            out.append(Text(f"  ✚ replan attempt {m['n']}/{m['m']}", style="magenta"))
            return out

        for key, prefix, style in (
            ("replan_stuck", "  ✚ replanner stuck at ", "magenta"),
            ("replan_newnode", "  ✚ new node ", "bold green"),
            ("replan_newedge", "  ✚ new edge ", "bold green"),
            ("replan_reject", "  ✗ rejected ", "red"),
            ("replan_giveup", "  ⚑ replanner ", "bold red"),
        ):
            m = _RE[key].search(line)
            if m:
                val = m["id"] if "id" in m.groupdict() and m.groupdict().get("id") else m.groupdict().get("rest", "")
                t = Text()
                t.append(prefix, style=style)
                t.append(_trunc(val, 72), style=style if "new" in key or "reject" in key else "grey62")
                out.append(t)
                return out

        m = _RE["orch_backtrack"].search(line)
        if m:
            out.append(Text(f"  ↩ backtrack to {m['id'].strip()}", style="grey58"))
            return out

        if _RE["orch_done"].search(line):
            out.append(Text("\n■ execution complete", style="bold white"))
            self.reset()
            return out

        if "[[UI_DONE]]" in line:
            out.append(Text("■ run finished", style="bold green"))
            return out
        if "[[UI_ERROR]]" in line:
            out.append(Text(f"■ {line}", style="bold red"))
            return out

        return out
