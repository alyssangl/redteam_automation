"""Offline tests for the credential-retry / anti-repeat refinement (W/X/Z).

  W: _config_key — same module + different options is a DIFFERENT config
     (so ssh_login can retry with new creds), identical config is the same.
  X: _expand_intent_to_node — intent's module_options/payload_options override
     the defaults; absence keeps defaults (backward-compatible).
  Z: _classify_msf_failure — credential failures (no credentials found / all
     login attempts failed / Authentication failed) classify as auth_failed.

No lab needed (lazy MSF). Run: python tests/test_credential_retry.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core_agents.orchestrator import (
    _config_key, _expand_intent_to_node, _classify_msf_failure,
)
from core_agents.attack_graph import AttackGraph, AttackNode


# --- W: _config_key ----------------------------------------------------------

def test_config_key_same_module_diff_creds_distinct():
    a = _config_key("auxiliary/scanner/ssh/ssh_login",
                    {"RHOSTS": "t", "USERNAME": "root", "PASSWORD": "root"})
    b = _config_key("auxiliary/scanner/ssh/ssh_login",
                    {"RHOSTS": "t", "USERNAME": "vagrant", "PASSWORD": "vagrant"})
    assert a != b


def test_config_key_identical_config_equal():
    opts = {"RHOSTS": "t", "USERNAME": "root", "PASSWORD": "root"}
    # order-independent
    assert _config_key("m", dict(opts)) == _config_key("m", dict(reversed(list(opts.items()))))


def test_config_key_different_module_distinct():
    assert _config_key("m1", {"RHOSTS": "t"}) != _config_key("m2", {"RHOSTS": "t"})


def test_config_key_empty_options_safe():
    assert _config_key("m", None) == _config_key("m", {})


# --- X: _expand_intent_to_node ----------------------------------------------

def _mk_graph():
    g = AttackGraph(objective="o", target_ip="10.0.0.5", attacker_ip="10.0.0.9")
    stuck = AttackNode(id="stuck", label="s", goal="g", agent_type="exploit")
    g.add_node(stuck)
    return g, stuck


def test_expand_merges_module_options_over_defaults():
    g, stuck = _mk_graph()
    intent = {"action": "use_module",
              "target_hint": "auxiliary/scanner/ssh/ssh_login",
              "module_options": {"USERNAME": "vagrant", "PASSWORD": "vagrant"}}
    node = _expand_intent_to_node(intent, g, stuck)
    assert node is not None
    assert node.module_options.get("RHOSTS") == "10.0.0.5"      # default kept
    assert node.module_options.get("RPORT") == 22               # ssh default kept
    assert node.module_options.get("USERNAME") == "vagrant"     # override applied
    assert node.module_options.get("PASSWORD") == "vagrant"


def test_expand_without_options_keeps_defaults_only():
    g, stuck = _mk_graph()
    intent = {"action": "use_module",
              "target_hint": "exploit/unix/ftp/proftpd_modcopy_exec"}
    node = _expand_intent_to_node(intent, g, stuck)
    assert node is not None
    assert node.module_options.get("RHOSTS") == "10.0.0.5"
    assert "USERNAME" not in node.module_options


def test_expand_intent_rhosts_override_wins():
    g, stuck = _mk_graph()
    intent = {"action": "use_module", "target_hint": "auxiliary/scanner/ssh/ssh_login",
              "module_options": {"RHOSTS": "10.0.0.99"}}
    node = _expand_intent_to_node(intent, g, stuck)
    assert node.module_options.get("RHOSTS") == "10.0.0.99"   # intent wins


def test_expand_payload_options_merge():
    g, stuck = _mk_graph()
    intent = {"action": "use_module", "target_hint": "exploit/unix/irc/unreal_ircd_3281_backdoor",
              "payload_options": {"LPORT": 5555}}
    node = _expand_intent_to_node(intent, g, stuck)
    assert node.payload_options.get("LHOST") == "10.0.0.9"   # default kept
    assert node.payload_options.get("LPORT") == 5555         # override applied


# --- Z: _classify_msf_failure -----------------------------------------------

def test_classify_no_credentials_found():
    cat, _ = _classify_msf_failure("[*] Bruteforce complete -- no credentials found")
    assert cat == "auth_failed", cat


def test_classify_all_login_attempts_failed():
    cat, _ = _classify_msf_failure("[-] 10.0.0.5:22 - All login attempts failed")
    assert cat == "auth_failed", cat


def test_classify_authentication_failed_still_works():
    cat, _ = _classify_msf_failure("Authentication failed for user root")
    assert cat == "auth_failed", cat


def test_classify_unrelated_is_not_auth():
    cat, _ = _classify_msf_failure("directory not writable")
    assert cat != "auth_failed", cat


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
