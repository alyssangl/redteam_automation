"""Offline unit tests for privesc._make_pair_safe (the v6 message-pairing fix).

No lab needed (MSF is lazy since v8). Run:
    python tests/test_pair_safe.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_core.messages import AIMessage, ToolMessage, HumanMessage
from stages.privesc import _make_pair_safe


def _tc(i):
    return {"name": "f", "args": {}, "id": i}


def _valid(ms):
    """True if every assistant tool_calls msg has a response for each id, and no
    orphan ToolMessage exists (the two 400s OpenAI raises)."""
    i = 0
    while i < len(ms):
        m = ms[i]
        if isinstance(m, AIMessage) and getattr(m, "tool_calls", None):
            need = {t["id"] for t in m.tool_calls}
            got = set(); j = i + 1
            while j < len(ms) and isinstance(ms[j], ToolMessage):
                got.add(ms[j].tool_call_id); j += 1
            if not need.issubset(got):
                return False
            i = j; continue
        if isinstance(m, ToolMessage):
            return False  # orphan tool message
        i += 1
    return True


def test_parallel_calls_missing_response():
    # the exact R5 crash: 2 parallel tool_calls, only 1 response
    msgs = [HumanMessage(content="go"),
            AIMessage(content="", tool_calls=[_tc("a"), _tc("b")]),
            ToolMessage(content="ra", tool_call_id="a")]
    out = _make_pair_safe(msgs)
    assert _valid(out)
    assert not any(isinstance(m, AIMessage) and m.tool_calls for m in out)


def test_parallel_calls_complete():
    msgs = [AIMessage(content="", tool_calls=[_tc("a"), _tc("b")]),
            ToolMessage(content="ra", tool_call_id="a"),
            ToolMessage(content="rb", tool_call_id="b")]
    out = _make_pair_safe(msgs)
    assert _valid(out) and len(out) == 3


def test_orphan_tool_dropped():
    msgs = [ToolMessage(content="x", tool_call_id="z"), HumanMessage(content="hi")]
    out = _make_pair_safe(msgs)
    assert _valid(out) and len(out) == 1


def test_plain_conversation_preserved():
    msgs = [HumanMessage(content="a"), AIMessage(content="hi"), HumanMessage(content="b")]
    out = _make_pair_safe(msgs)
    assert len(out) == 3


def test_nonmatching_response_dropped():
    # response id doesn't match the tool_call id -> group incomplete -> both dropped
    msgs = [AIMessage(content="", tool_calls=[_tc("a")]),
            ToolMessage(content="r", tool_call_id="q")]
    out = _make_pair_safe(msgs)
    assert _valid(out)


def test_single_call_matched():
    msgs = [AIMessage(content="", tool_calls=[_tc("a")]),
            ToolMessage(content="r", tool_call_id="a")]
    out = _make_pair_safe(msgs)
    assert _valid(out) and len(out) == 2


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
