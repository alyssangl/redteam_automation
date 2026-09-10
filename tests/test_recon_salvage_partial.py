"""Offline tests for the recon retry-budget SALVAGE seam.

Bug this guards: recon's intended "salvage a usable scan at the retry budget"
branch was dead code — route_after_critic ends the graph at loop_step>=MAX before
the critic is re-entered, so a flaky run where the LLM critic returned FAIL 3x
would report success=False and make the walker skip the WHOLE downstream chain,
even when a perfectly usable scan (real IP + several open ports) was in hand.

critic_node now salvages a PASS-with-partial at the budget boundary IFF a real
target IP AND >=3 distinct open ports were actually found. These tests stub the
LLM critic (no lab, no API) and assert the salvage fires only when it should.

Run:
    python tests/test_recon_salvage_partial.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_core.messages import AIMessage
import stages.recon as recon
from stages.recon import critic_node, MAX_RECON_RETRIES

# A raw nmap blob with a real target (not KALI_IP) and >=3 distinct open ports.
_GOOD_SCAN = """\
Nmap scan report for 192.168.34.7
22/tcp   open  ssh     OpenSSH 7.9p1
80/tcp   open  http    Apache 2.4.38
445/tcp  open  microsoft-ds Samba 4.3
6667/tcp open  irc     UnrealIRCd
"""

# A blob with only ONE open port — below the salvage bar.
_THIN_SCAN = """\
Nmap scan report for 192.168.34.7
22/tcp   open  ssh     OpenSSH 7.9p1
"""


def _stub_fail_critic():
    """Make the LLM critic always return a FAIL verdict (no API)."""
    recon.call_llm = lambda *a, **k: AIMessage(content="VERDICT: FAIL\nFEEDBACK: not enough")


def _state(scan_results, loop_step):
    return {
        "messages": [AIMessage(content="prior executor summary")],
        "scan_results": scan_results,
        "plan": "scan 192.168.34.7",
        "goal": "enumerate",
        "loop_step": loop_step,
    }


def test_salvages_usable_scan_at_budget_boundary():
    orig = recon.call_llm
    try:
        _stub_fail_critic()
        # loop_step = MAX-1 -> new_step reaches MAX this call -> budget boundary.
        out = critic_node(_state(_GOOD_SCAN, MAX_RECON_RETRIES - 1))
        assert out["critic_verdict"] == "PASS", out["critic_verdict"]
        assert out["target_info"]["ip"] == "192.168.34.7"
        assert len(out["target_info"]["ports"]) >= 3
    finally:
        recon.call_llm = orig


def test_no_salvage_before_budget_boundary():
    # A FAIL on an EARLIER retry must still FAIL (so the planner gets to retry).
    orig = recon.call_llm
    try:
        _stub_fail_critic()
        out = critic_node(_state(_GOOD_SCAN, 0))
        assert out["critic_verdict"] == "FAIL", out["critic_verdict"]
    finally:
        recon.call_llm = orig


def test_no_salvage_when_scan_is_thin():
    # At the boundary but only 1 open port -> stays FAIL (cannot mask an empty scan).
    orig = recon.call_llm
    try:
        _stub_fail_critic()
        out = critic_node(_state(_THIN_SCAN, MAX_RECON_RETRIES - 1))
        assert out["critic_verdict"] == "FAIL", out["critic_verdict"]
    finally:
        recon.call_llm = orig


def test_real_pass_still_passes():
    # A genuine PASS verdict is untouched by the salvage path.
    orig = recon.call_llm
    try:
        recon.call_llm = lambda *a, **k: AIMessage(content=(
            'VERDICT: PASS\nTARGET_INFO:\n{"ip":"192.168.34.7","os":"Linux",'
            '"hostname":"ms3","ports":[{"port":22,"state":"open","service":"ssh","version":""}]}'
        ))
        out = critic_node(_state(_GOOD_SCAN, 0))
        assert out["critic_verdict"] == "PASS", out["critic_verdict"]
    finally:
        recon.call_llm = orig


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
