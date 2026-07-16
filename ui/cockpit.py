"""Live run cockpit — a Textual TUI to launch an orchestrator run and watch the
walker/judge/replanner drive and mutate the attack graph in real time.

Layout:
    ┌ sidebar ─┬ live graph ────────┬ raw ticker ─────┐
    │ launcher │ nodes recolor;     │ full firehose   │
    │  form    │ ✚replan badges     │ colorized by    │
    │          ├────────────────────┤ marker          │
    │ Run/Stop │ activity feed:     │ (ANSI-stripped) │
    │          │ round·plan·critic  │                 │
    │          │ ⚖judge  ✚replanner │                 │
    └──────────┴────────────────────┴─────────────────┘

The run itself is an isolated subprocess (ui/headless_run.py). We stream its
merged stdout/stderr into both the raw ticker and the structured activity feed
(ui/activity.py), and poll the checkpoint JSON for the graph. Nothing heavy is
imported here, so the TUI stays snappy.

Run:  python -m ui.cockpit
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, Footer, Header, Input, RichLog, Select, Static
from rich.text import Text

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ui.registry import list_graph_keys  # noqa: E402
from ui.render import render_graph  # noqa: E402
from ui.activity import ActivityParser, strip_ansi  # noqa: E402

DEFAULT_TARGET = "192.168.34.7"
DEFAULT_ATTACKER = "192.168.34.6"


def colorize(line: str) -> Text:
    """Style a raw log line by its marker so the ticker is scannable."""
    line = strip_ansi(line)
    low = line.lower()
    style = "grey70"
    if "[[ui_error]]" in low or line.startswith("[[UI_ERROR]]"):
        style = "bold red"
    elif "[[ui_done]]" in low:
        style = "bold green"
    elif "[[ui_meta]]" in low:
        style = "bold cyan"
    elif "[replanner]" in low:
        if "new node" in low or "new edge" in low:
            style = "bold green"
        elif "rejected" in low or "gave up" in low or "exhausted" in low or "not found" in low:
            style = "red"
        else:
            style = "magenta"
    elif "[judge]" in low:
        if "escalate" in low:
            style = "bold magenta"
        elif "adapt" in low:
            style = "yellow"
        else:
            style = "cyan"
    elif "[dispatch]" in low:
        style = "blue"
    elif "session" in low and "opened" in low:
        style = "bold green"
    elif "[direct]" in low:
        style = "grey50"
    elif "traceback" in low or "error" in low or "fail" in low:
        style = "red"
    elif "[orchestrator]" in low:
        style = "white"
    return Text(line, style=style)


class Cockpit(App):
    TITLE = "lgg_automation — run cockpit"

    CSS = """
    #sidebar { width: 36; border-right: solid $panel; padding: 1; }
    #sidebar Static.field-label { color: $text-muted; margin-top: 1; }
    #buttons { height: auto; margin-top: 1; }
    #buttons Button { width: 1fr; }
    #status { margin-top: 1; height: auto; }
    #center { width: 1fr; }
    .pane-title { color: $text-muted; text-style: bold; padding: 0 1; }
    /* graph pane trimmed so the (now much richer) activity feed gets the room */
    #graphpane { height: 32%; border-bottom: solid $panel; padding: 0 1; }
    #activity { height: 1fr; padding: 0 1; }
    #stream { width: 40; border-left: solid $panel; padding: 0 1; }
    """

    BINDINGS = [
        ("r", "run", "Run"),
        ("s", "stop", "Stop"),
        ("c", "clear", "Clear log"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._proc: asyncio.subprocess.Process | None = None
        self._checkpoint: Path | None = None
        self._activity = ActivityParser()

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("graph", classes="field-label")
                keys = list_graph_keys()
                yield Select(
                    [(k, k) for k in keys],
                    value=("goal_only" if "goal_only" in keys else keys[0]),
                    allow_blank=False,
                    id="graph",
                )
                yield Static("target ip", classes="field-label")
                yield Input(value=DEFAULT_TARGET, id="target")
                yield Static("attacker ip", classes="field-label")
                yield Input(value=DEFAULT_ATTACKER, id="attacker")
                yield Checkbox("explore (replanner)", value=True, id="explore")
                yield Checkbox("use judge", value=True, id="judge")
                with Horizontal(id="buttons"):
                    yield Button("Run", variant="success", id="run")
                    yield Button("Stop", variant="error", id="stop")
                yield Static("idle", id="status")
            with Vertical(id="center"):
                yield Static("graph", classes="pane-title")
                with VerticalScroll(id="graphpane"):
                    yield Static(render_graph(None), id="graph_view")
                yield Static("activity — rounds · judge · replanner", classes="pane-title")
                yield RichLog(id="activity", wrap=True, markup=False, highlight=False)
            yield RichLog(id="stream", wrap=True, markup=False, highlight=False)
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(1.0, self._refresh_graph)
        self._set_status("idle", "grey62")

    # -- helpers --------------------------------------------------------------

    def _set_status(self, text: str, color: str = "white") -> None:
        self.query_one("#status", Static).update(Text(text, style=color))

    def _refresh_graph(self) -> None:
        if not self._checkpoint or not self._checkpoint.exists():
            return
        try:
            data = json.loads(self._checkpoint.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return  # mid-write; try again next tick
        self.query_one("#graph_view", Static).update(render_graph(data))

    # -- actions --------------------------------------------------------------

    def action_run(self) -> None:
        if self._proc is not None:
            self._log_line(Text("a run is already in progress — Stop it first", style="yellow"))
            return
        key = self.query_one("#graph", Select).value
        target = self.query_one("#target", Input).value.strip() or DEFAULT_TARGET
        attacker = self.query_one("#attacker", Input).value.strip() or DEFAULT_ATTACKER
        explore = self.query_one("#explore", Checkbox).value
        judge = self.query_one("#judge", Checkbox).value

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._checkpoint = ROOT / "graphs" / f"_ui_{key}_{stamp}.json"

        cmd = [
            sys.executable, "-u", str(ROOT / "ui" / "headless_run.py"),
            "--graph", str(key),
            "--target", target,
            "--attacker", attacker,
            "--checkpoint", str(self._checkpoint),
            "--judge" if judge else "--no-judge",
        ]
        if explore:
            cmd.append("--explore")

        self.query_one("#stream", RichLog).clear()
        self.query_one("#activity", RichLog).clear()
        self._activity.reset()
        self._log_line(Text(f"launching {key}  explore={explore} judge={judge}  → {target}", style="bold white"))
        self._set_status(f"running {key}…", "yellow")
        self._stream_run(cmd)

    def action_stop(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
        except ProcessLookupError:
            pass
        self._set_status("stopping…", "red")

    def action_clear(self) -> None:
        self.query_one("#stream", RichLog).clear()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run":
            self.action_run()
        elif event.button.id == "stop":
            self.action_stop()

    def _log_line(self, text: Text) -> None:
        self.query_one("#stream", RichLog).write(text)

    # -- worker ---------------------------------------------------------------

    @work(exclusive=True, group="run")
    async def _stream_run(self, cmd: list[str]) -> None:
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(ROOT),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception as exc:  # noqa: BLE001
            self._log_line(Text(f"failed to launch: {exc}", style="bold red"))
            self._set_status("launch failed", "red")
            self._proc = None
            return

        assert self._proc.stdout is not None
        stream = self.query_one("#stream", RichLog)
        activity = self.query_one("#activity", RichLog)
        while True:
            raw = await self._proc.stdout.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line:
                continue
            stream.write(colorize(line))
            for entry in self._activity.feed(line):
                activity.write(entry)

        rc = await self._proc.wait()
        self._proc = None
        self._refresh_graph()
        if rc == 0:
            self._set_status("finished ✓", "green")
        elif rc in (130, -15, 15):
            self._set_status("stopped", "red")
        else:
            self._set_status(f"exited (code {rc})", "red")


def main() -> None:
    Cockpit().run()


if __name__ == "__main__":
    main()
