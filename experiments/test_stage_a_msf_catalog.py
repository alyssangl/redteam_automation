"""
Offline test for Stage A — MSF catalog validation.

Verifies that _replan_from rejects proposals whose module path isn't in
MSF's actual installed catalog, treating an unavailable catalog as
"validation disabled" (failsafe so a disconnected MSF doesn't break us).

Run: python experiments/test_stage_a_msf_catalog.py
"""

from __future__ import annotations

import json
import logging
import sys
import types
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ---- Fake tools.metasploit_tools with a controllable catalog ---------------
_fake_msf = types.ModuleType("tools.metasploit_tools")


class _FakeModules:
    """Stand-in for client.modules with .exploits/.auxiliary/.post lists."""
    def __init__(self):
        # Default to a small known-good catalog
        self.exploits = [
            "unix/ftp/proftpd_modcopy_exec",
            "multi/samba/usermap_script",
            "linux/samba/is_known_pipename",
            "multi/http/apache_mod_cgi_bash",
        ]
        self.auxiliary = ["scanner/ssh/ssh_login"]
        self.post = []


class _FakeClient:
    def __init__(self):
        self.modules = _FakeModules()


class _FakeMsfSession:
    def __init__(self):
        self.client = _FakeClient()
    def send_command(self, *a, **kw): return ""
    def run_session_command(self, *a, **kw): return ""


_fake_msf.msf_session = _FakeMsfSession()
_fake_msf.MetasploitSession = lambda *a, **kw: _FakeMsfSession()
_fake_msf.tool_session_command = lambda session_id, command: ""
sys.modules["tools.metasploit_tools"] = _fake_msf
# -----------------------------------------------------------------------------

from core_agents.attack_graph import AttackGraph, AttackNode
import core_agents.orchestrator as orch


PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
results = []


def check(label, cond, detail=""):
    icon = PASS if cond else FAIL
    print(f"  {icon} {label}" + (f" -- {detail}" if detail else ""))
    results.append((label, cond))


def make_logger():
    buf = StringIO()
    log = logging.getLogger(f"sa_{id(buf)}")
    log.handlers.clear()
    log.setLevel(logging.DEBUG)
    h = logging.StreamHandler(buf)
    h.setLevel(logging.DEBUG)
    log.addHandler(h)
    log.propagate = False
    return log, buf


def llm_returning(payload):
    def _stub(messages, system_prompt=None, **kw):
        class R:
            content = json.dumps(payload)
        return R()
    return _stub


def reset_catalog():
    """Clear the lazy cache between tests so each test gets a fresh load."""
    orch._MSF_MODULE_CATALOG = None


def make_graph():
    g = AttackGraph.create(
        objective="test", target_ip="10.0.0.5", attacker_ip="10.0.0.1",
        name="sa_test",
    )
    recon = AttackNode(id="recon", label="recon", agent_type="recon")
    recon.mark_success(
        findings={"success": True,
                  "ports": [{"port": 445, "service": "smb",
                             "version": "Samba 4.3.11"}]},
        summary="recon",
    )
    g.add_node(recon)
    return g


# -----------------------------------------------------------------------------
# Test 1 — _load_msf_module_catalog returns the expected set
# -----------------------------------------------------------------------------

def test_load_catalog():
    print("\n[Test 1] _load_msf_module_catalog loads from fake RPC")
    reset_catalog()
    log, _ = make_logger()
    cat = orch._load_msf_module_catalog(log)

    check("catalog non-empty", len(cat) > 0,
          detail=f"size={len(cat)}")
    check("known real module in catalog",
          "exploit/multi/samba/usermap_script" in cat)
    check("known auxiliary in catalog",
          "auxiliary/scanner/ssh/ssh_login" in cat)
    check("hallucinated path NOT in catalog",
          "exploit/linux/samba/usermap_script" not in cat)


# -----------------------------------------------------------------------------
# Test 2 — second call hits the cache (no second RPC roundtrip)
# -----------------------------------------------------------------------------

def test_catalog_cached():
    print("\n[Test 2] catalog is loaded once and cached")
    reset_catalog()
    log, _ = make_logger()
    orch._load_msf_module_catalog(log)

    # Mutate the underlying fake to detect a second load
    _fake_msf.msf_session.client.modules.exploits = ["MUTATED"]
    cat2 = orch._load_msf_module_catalog(log)

    check("cache still returns original set (not mutated)",
          "exploit/multi/samba/usermap_script" in cat2)
    check("MUTATED entry NOT in returned set",
          "exploit/MUTATED" not in cat2)

    # Restore for subsequent tests
    _fake_msf.msf_session.client.modules.exploits = [
        "unix/ftp/proftpd_modcopy_exec",
        "multi/samba/usermap_script",
        "linux/samba/is_known_pipename",
        "multi/http/apache_mod_cgi_bash",
    ]


# -----------------------------------------------------------------------------
# Test 3 — _module_exists_in_msf
# -----------------------------------------------------------------------------

def test_module_exists():
    print("\n[Test 3] _module_exists_in_msf decisions")
    reset_catalog()
    log, _ = make_logger()

    check("real module -> True",
          orch._module_exists_in_msf("exploit/multi/samba/usermap_script", log))
    check("hallucinated path -> False",
          not orch._module_exists_in_msf(
              "exploit/linux/samba/usermap_script", log))
    check("totally bogus -> False",
          not orch._module_exists_in_msf("exploit/foo/bar/baz", log))


# -----------------------------------------------------------------------------
# Test 4 — catalog load failure -> validation disabled (failsafe)
# -----------------------------------------------------------------------------

def test_load_failure_failsafe():
    print("\n[Test 4] catalog load failure -> _module_exists_in_msf returns True (failsafe)")
    reset_catalog()
    # Break the fake so the loader raises
    orig_client = _fake_msf.msf_session.client
    _fake_msf.msf_session.client = None  # AttributeError on .modules
    log, buf = make_logger()
    try:
        result = orch._module_exists_in_msf("exploit/foo/bar/baz", log)
    finally:
        _fake_msf.msf_session.client = orig_client

    check("returns True (failsafe -- don't block on disconnected MSF)", result is True)
    check("log mentions 'Load failed'", "Load failed" in buf.getvalue())


# -----------------------------------------------------------------------------
# Test 5 — _replan_from rejects hallucinated module proposal
# -----------------------------------------------------------------------------

def test_replan_rejects_hallucinated():
    print("\n[Test 5] _replan_from rejects a hallucinated module path")
    reset_catalog()
    g = make_graph()
    log, buf = make_logger()

    orig = orch.call_llm
    orch.call_llm = llm_returning({
        "action": "use_module",
        "target_hint": "exploit/linux/samba/usermap_script",  # hallucinated
        "rationale": "samba detected",
    })
    try:
        result = orch._replan_from(g, "recon", log)
    finally:
        orch.call_llm = orig

    check("returns None", result is None,
          detail=f"got {result!r}")
    check("log says REJECTED ... not in MSF catalog",
          "not in MSF catalog" in buf.getvalue())


# -----------------------------------------------------------------------------
# Test 6 — real module IS accepted
# -----------------------------------------------------------------------------

def test_replan_accepts_real_module():
    print("\n[Test 6] _replan_from accepts a real module path")
    reset_catalog()
    g = make_graph()
    log, _ = make_logger()

    orig = orch.call_llm
    orch.call_llm = llm_returning({
        "action": "use_module",
        "target_hint": "exploit/multi/samba/usermap_script",  # real
        "rationale": "samba detected",
    })
    try:
        result = orch._replan_from(g, "recon", log)
    finally:
        orch.call_llm = orig

    check("returns a node id (not None)", result is not None,
          detail=f"got {result!r}")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Stage A offline check -- MSF catalog validation")
    print("=" * 70)

    test_load_catalog()
    test_catalog_cached()
    test_module_exists()
    test_load_failure_failsafe()
    test_replan_rejects_hallucinated()
    test_replan_accepts_real_module()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print()
    print("=" * 70)
    if passed == total:
        print(f"  ALL {total} CHECKS PASSED")
        sys.exit(0)
    else:
        print(f"  {passed}/{total} checks passed -- {total - passed} FAILED")
        sys.exit(1)
