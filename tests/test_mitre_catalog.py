"""Offline tests for the MITRE technique catalog (core_agents/mitre.py).

The catalog is the shared vocabulary for the technique/procedure boundary: the
replanner's menu and the subagents' scope contract both read from it. These guard
the lookup helpers and the persistence menu's alignment with the stage's slugs.

No lab. Run: python tests/test_mitre_catalog.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core_agents import mitre


def test_persistence_menu_ordered_and_slugged():
    menu = mitre.technique_menu("persistence")
    slugs = [t.slug for t in menu]
    # slugs must match persistence _classify() outputs so findings/critic/catalog agree
    for expected in ("cron_job", "ssh_key", "user_account", "systemd_service", "bash_profile"):
        assert expected in slugs, f"{expected} missing from persistence menu"
    # least-privilege-first: cron before the root-only techniques
    assert slugs.index("cron_job") < slugs.index("user_account")
    assert slugs.index("cron_job") < slugs.index("systemd_service")


def test_get_technique_by_id_and_slug():
    by_slug = mitre.get_technique("persistence", "cron_job")
    by_id = mitre.get_technique("persistence", "T1053.003")
    assert by_slug is not None and by_slug is by_id, "id and slug must resolve to same technique"
    assert mitre.get_technique("persistence", "nope") is None
    assert mitre.get_technique("persistence", "") is None


def test_resolve_any_across_tactics():
    t = mitre.resolve_any("T1068")
    assert t is not None and t.tactic == "privilege_escalation"


def test_next_untried_skips_failed():
    # cron already failed -> next available should be ssh_key (user-level, before root ones)
    nxt = mitre.next_untried("persistence", failed=["cron_job"],
                             access_level="user", session_type="command_shell")
    assert nxt is not None and nxt.slug == "ssh_key", nxt


def test_next_untried_by_id_and_privilege_gating():
    # user-level session must not be offered root-only techniques
    nxt = mitre.next_untried("persistence",
                             failed=["T1053.003", "T1098.004", "T1546.004"],
                             access_level="user", session_type="command_shell")
    # remaining are user_account/systemd_service — both root-only -> exhausted for a user
    assert nxt is None, f"user session should exhaust after user-level techniques, got {nxt}"
    # a root session, same failures, still has user_account/systemd available
    nxt_root = mitre.next_untried("persistence",
                                  failed=["T1053.003", "T1098.004", "T1546.004"],
                                  access_level="root", session_type="command_shell")
    assert nxt_root is not None and nxt_root.slug in ("user_account", "systemd_service")


def test_next_untried_exhaustion_returns_none():
    allslugs = [t.slug for t in mitre.technique_menu("persistence")]
    assert mitre.next_untried("persistence", failed=allslugs,
                              access_level="root", session_type="command_shell") is None


def test_menu_summary_marks_states():
    s = mitre.menu_summary("persistence", failed=["cron_job"],
                           access_level="user", session_type="command_shell")
    assert "cron_job" in s and "TRIED" in s
    assert "AVAILABLE" in s          # ssh_key should be available
    assert "N/A" in s                # a root-only technique for a user session


def test_unknown_tactic_is_empty_not_crash():
    assert mitre.technique_menu("nonsense") == []
    assert mitre.next_untried("nonsense", failed=[]) is None


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
