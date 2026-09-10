"""Offline tests for the cockpit's middle-section activity feed (ui/activity.py)
and a headless smoke test that the Textual app actually composes.

The activity parser turns the run stream into the structured middle pane. These
feed it REAL orchestrator/subagent lines (the exact formats a live run emits) and
assert the feed surfaces what the operator needs to see:
  - the actual COMMANDS being run (nmap / msf / session echo+cat)
  - the REPLANNER changing the flow (GROW TECHNIQUE + inherited successors)
  - session upgrades, and NO spinner/`running` noise.

The Pilot test drives the real Cockpit app with Textual's headless test harness
(no TTY needed) to prove the TUI composes and its panes exist.

No lab. Run: python tests/test_ui_activity.py
"""
import sys, os, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.activity import ActivityParser, strip_ansi


def _feed_all(lines):
    """Feed lines through a fresh parser, return the flat list of plain strings."""
    p = ActivityParser()
    out = []
    for ln in lines:
        for entry in p.feed(ln):
            out.append(entry.plain)
    return out


def test_shows_executed_commands():
    lines = [
        "[Dispatch] node='recon' label='Discover Attack Surface' agent=recon explore=True",
        "[Terminal Tool] Executing: nmap -Pn -sS -T4 --top-ports 1000 192.168.34.7",
    ]
    out = _feed_all(lines)
    assert any("run" in s and "nmap -Pn -sS" in s for s in out), out


def test_shows_session_commands_with_sid():
    lines = [
        "[Dispatch] node='file_drop' label='Drop Proof' agent=impact explore=True",
        "[direct] session(18)> echo 'PWNED' > /tmp/pwned_flaw_persist.txt",
        "[direct] session(18)> cat /tmp/pwned_flaw_persist.txt",
    ]
    out = _feed_all(lines)
    assert any("echo 'PWNED'" in s and "session 18" in s for s in out), out
    assert any("cat /tmp/pwned" in s for s in out), out


def test_shows_msf_run_but_not_set_noise():
    lines = [
        "[Dispatch] node='gain_access' label='x' agent=exploit explore=True",
        "[direct] > use exploit/unix/irc/unreal_ircd_3281_backdoor",
        "[direct] > set RHOSTS 192.168.34.7",   # noise — must be dropped
        "[direct] RHOSTS => 192.168.34.7",       # noise — must be dropped
        "[direct] > run",
    ]
    out = _feed_all(lines)
    assert any("use exploit/unix/irc" in s for s in out), out
    assert any(s.strip().endswith("msf: run") for s in out), out
    assert not any("set RHOSTS" in s for s in out), "msf `set` echoes must not flood the feed"
    assert not any("=>" in s for s in out), "datastore echoes must be dropped"


def test_replanner_grow_technique_with_inherited_successors():
    # The key flow-change event — must be shown (old parser only knew NEW NODE/EDGE).
    line = ("[Replanner] GROW TECHNIQUE: persistence_cron_job (T1053.003 Scheduled Task/Job: "
            "Cron) — cron_job is available [inherits successors: ['file_drop']]")
    out = _feed_all([line])
    assert any("grow technique" in s and "persistence_cron_job" in s for s in out), out
    assert any("file_drop" in s for s in out), "must surface the inherited successor"


def test_shows_session_upgrade():
    line = ("[Persistence Probe] UPGRADE SUCCESS — new meterpreter session 18 on "
            "192.168.34.7 (from command_shell 16).")
    out = _feed_all([line])
    assert any("upgraded" in s and "meterpreter 18" in s for s in out), out


def test_running_status_is_not_echoed():
    # "▶ agent · node" is the start marker; STATUS → running would double it.
    out = _feed_all(["[persist] STATUS → running"])
    assert out == [], f"running status must produce no feed line, got {out}"


def test_spinner_chatter_is_filtered():
    lines = [
        "[Dispatch] node='recon' label='x' agent=recon explore=True",
        "[Recon Planner] Designing scan strategy...",   # chatter
        "[Recon Planner] PERSISTENCE PLAN:",            # bare header chatter
        "[Recon Planner] Strategy: scan all ports then version-detect",  # real content
    ]
    out = _feed_all(lines)
    assert not any("Designing scan strategy" in s for s in out), out
    assert not any(s.strip().endswith("PERSISTENCE PLAN:") for s in out), out
    assert any("scan all ports" in s for s in out), "real plan content must survive"


def test_critic_verdict_deduped():
    lines = [
        "[Dispatch] node='recon' label='x' agent=recon explore=True",
        "[Recon Critic] Evaluating scan quality...",   # chatter
        "[Recon Critic] VERDICT: PASS",
        "[Recon Critic] Verdict: PASS",                # duplicate verdict
        "[Recon Critic] PASS — VERDICT: PASS",         # duplicate verdict
    ]
    crit = [s for s in _feed_all(lines) if "critic" in s]
    assert len(crit) == 1, f"repeated PASS verdicts must collapse to one line, got {crit}"


def test_full_real_log_narrative():
    # End-to-end against this session's real green run: the feed must contain the
    # whole flaw->recover story with no crashes.
    log = os.path.join(os.path.dirname(__file__), "..", "logs", "flaw_persist_b3_verify5.log")
    if not os.path.exists(log):
        print("  (skip full-log test — logs/flaw_persist_b3_verify5.log not present)")
        return
    with open(log, encoding="utf-8", errors="replace") as fh:
        out = _feed_all(fh)
    joined = "\n".join(out)
    for needle in ("nmap -Pn", "grow technique persistence_cron_job",
                   "upgraded command_shell", "file_drop", "execution complete"):
        assert needle in joined, f"expected {needle!r} in the parsed feed"


def test_cockpit_composes_headless():
    """Drive the REAL Textual app with the headless test harness (no TTY)."""
    async def _run():
        from ui.cockpit import Cockpit
        app = Cockpit()
        async with app.run_test(size=(120, 40)) as pilot:
            # the three panes + live-graph view must exist
            for wid in ("#graph", "#target", "#activity", "#stream", "#graph_view"):
                assert app.query_one(wid) is not None, f"missing widget {wid}"
            # feed a line through the app's parser into the activity log (smoke path)
            entries = app._activity.feed(
                "[Dispatch] node='recon' label='Discover' agent=recon explore=True")
            app.query_one("#activity").write(entries[0] if entries else "")
            await pilot.pause()
        return True
    assert asyncio.run(_run())


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    import warnings; warnings.filterwarnings("ignore")
    fails = 0
    for t in TESTS:
        try:
            t(); print(f"PASS {t.__name__}")
        except Exception as e:
            fails += 1; print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(TESTS)-fails}/{len(TESTS)} passed")
    sys.exit(1 if fails else 0)
