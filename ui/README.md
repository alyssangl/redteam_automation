# ui/ — live run cockpit (Textual TUI)

A terminal cockpit to **launch an orchestrator run and watch it work in real
time** — pick a graph + target + flags, hit Run, and watch the graph mutate while
a structured feed narrates each subagent round, judge verdict, and replanner step.
Built so experiments go smoothly (no more tailing a raw log file) and, incidentally,
to make the kill-chain adaptation legible for demos/figures.

Three panes:

- **left** — launcher (graph picker, target/attacker IPs, `explore`/`judge` toggles, Run/Stop)
- **middle** — *live graph* (nodes recolor by status, replanner nodes badged `✚replan`)
  on top, and a *structured activity feed* below: one block per node execution
  (`round → plan → run → critic → result`). The feed surfaces the detail an operator
  wants to see, not just status:
  - **the actual commands** being run — `run nmap …`, `run msf: use …`, and target
    session commands with their id (`run echo 'PWNED' … (session 18)`).
  - **the replanner changing the flow** — `✚ grow technique persistence_cron_job
    (T1053.003) ↦ inherits ['file_drop']`, `✚ replan attempt 1/10`, `↩ backtrack to …`.
  - **session lifecycle** — `⇈ upgraded command_shell → meterpreter 18`, `◆ session opened`.
  - `⚖ judge` verdicts, deduped `critic` results, and stage summaries (`↳ … (session 18, root)`).
  Spinner chatter (`Selecting technique…`) and redundant `running` echoes are filtered.
  This is the parsed, human-readable view (`ui/activity.py`, unit-tested against real logs).
- **right** — the raw colorized ticker (the full firehose, ANSI-stripped)

## Run it

```bash
pip install textual        # already pinned in requirements.txt
python -m ui.cockpit       # or: python ui/cockpit.py
```

Keys: **r** run · **s** stop · **c** clear log · **q** quit. The sidebar has the
graph picker (all `examples/*_graph.py` are auto-discovered), target/attacker IPs,
and the `explore` (replanner) / `use judge` toggles — the same knobs as
`run_graph(..., explore=, use_judge=)`.

> A live run needs the lab up (see `HANDOFF.md` §4.3). Without it, the cockpit
> still launches and renders the graph plan — the run just fails fast at recon,
> which you'll see in the decision stream.

## How it works (design)

The run is an **isolated subprocess**, not an in-process thread. This matters
because the orchestrator's console logging writes to the terminal, which would
fight Textual for control. Instead:

```
 cockpit.py (Textual)                    headless_run.py (subprocess)
 ─────────────────────                   ────────────────────────────
 spawn ───────────────────────────────► build graph → save initial checkpoint
 read merged stdout/stderr  ◄─────────── run_graph(...) logs to stderr
   → colorized decision ticker             (+ [[UI_META]]/[[UI_DONE]] sentinels)
 poll graphs/_ui_<key>_<ts>.json ◄─────── _checkpoint() writes after every node
   → re-render live graph                  AND after every replanner mutation
```

- **Activity feed** (middle) = the same stream parsed by `activity.py` into grouped,
  structured lines. It keys off the stage prints (`[Recon Planner]`, `[Parameter
  Solver]`, `[* Critic]`, …) that go to stdout and *never reach the .log file* —
  so the cockpit shows more than tailing the log would. Pure `str -> list[Text]`,
  unit-testable against a real log.
- **Raw ticker** (right) = the subprocess's merged output, ANSI-stripped and
  colorized by marker (`[Replanner] NEW NODE/EDGE` green, `[Judge] escalate`
  magenta, `adapt` yellow, `[Dispatch]` blue, sessions green, errors red).
- **Live graph** (middle top) = the checkpoint JSON, polled once a second and
  rendered by `render.py`. Because `_checkpoint()` fires after each node *and* each
  graph mutation, new replanner nodes appear as the run grows them (badged `✚replan`).

Nothing heavy is imported in the cockpit process — `registry.list_graph_keys()`
is a pure filename scan, and rendering works straight off the serialized dict, so
the TUI never pulls in langchain/orchestrator.

## Files

| File | Purpose |
|---|---|
| `cockpit.py` | The Textual app — launcher form, live graph + activity panes, raw ticker, subprocess worker |
| `headless_run.py` | Subprocess entrypoint: build graph → initial checkpoint → `run_graph` |
| `registry.py` | Discover `examples/*_graph.py` builders (`list_graph_keys` / `resolve_builder`) |
| `render.py` | Checkpoint-dict → Rich renderable (status glyphs, edges, replanner badges) |
| `activity.py` | Parse the run stream → structured feed (`ActivityParser`, `strip_ansi`) |

## Not yet (v1 is the live cockpit only)

- Ablation / comparison board (load finished `logs/` + `graphs/` runs, compare
  success rate / steps / mutation count across configs — what the *paper* needs).
  The event/data model here (checkpoint JSON + marker stream) is meant to extend
  to it without rework.
- Replay mode (feed an old `logs/*.log` into the ticker offline).
