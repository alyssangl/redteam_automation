"""Offline tests — persistence subagent honors the node's assigned MITRE technique.

The node (graph author or replanner) chooses the technique; the subagent chooses
the procedure under it. When a technique is assigned, the planner's menu is scoped
to that ONE technique's procedures with a LOCK banner; unassigned falls back to the
full self-select menu (backward compatible).

Pure-function tests (no lab, no LLM). Run:
    python tests/test_persistence_assigned_technique.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.persistence as ps


def test_classify_slugs_match_catalog():
    assert ps.classify_technique("Cron job backdoor") == "cron_job"
    assert ps.classify_technique("SSH authorized_keys injection") == "ssh_key"
    assert ps.classify_technique("New user account with SSH") == "user_account"
    assert ps.classify_technique("Bash profile backdoor") == "shell_profile"
    assert ps.classify_technique("nothing here") == "unknown"


def test_unassigned_returns_full_menu():
    out = ps._get_recommended_techniques("root", "command_shell", "1", only_slug="")
    assert "RECOMMENDED TECHNIQUES" in out
    # full menu shows multiple distinct techniques
    assert "Cron job backdoor" in out
    assert "SSH authorized_keys injection" in out
    assert "ASSIGNED MITRE TECHNIQUE" not in out


def test_assigned_cron_scopes_to_cron_only():
    out = ps._get_recommended_techniques("root", "command_shell", "1", only_slug="cron_job")
    assert "ASSIGNED MITRE TECHNIQUE" in out
    assert "T1053.003" in out
    assert "LOCKED" in out
    assert "Cron job backdoor" in out
    # must NOT offer other techniques to switch to
    assert "SSH authorized_keys injection" not in out
    assert "New user account" not in out


def test_assigned_ssh_scopes_to_ssh_only():
    out = ps._get_recommended_techniques("root", "command_shell", "1", only_slug="ssh_key")
    assert "T1098.004" in out
    assert "SSH authorized_keys injection" in out
    assert "Cron job backdoor" not in out


def test_assigned_technique_without_prebuilt_procedure_uses_hint_and_rag():
    # systemd has a catalog entry but no bundled procedure in _get_recommended_techniques
    out = ps._get_recommended_techniques("root", "command_shell", "1", only_slug="systemd_service")
    assert "ASSIGNED MITRE TECHNIQUE" in out
    assert "T1543.002" in out
    assert "No pre-built procedure" in out
    assert "query_knowledge_base" in out
    # the catalog procedure_hint is surfaced
    assert "systemd" in out.lower()


def test_assigned_banner_overrides_switch_guidance():
    out = ps._get_recommended_techniques("user", "command_shell", "1", only_slug="cron_job")
    assert "do NOT" in out and "switch" in out
    assert "TECHNIQUE_EXHAUSTED" in out


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
