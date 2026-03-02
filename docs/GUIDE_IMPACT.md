# Implementation Guide: Impact Stage

> **Standalone prompt** — contains everything needed to implement `stages/impact.py`.
> No other guide needs to be read.

---

## 1. Overview

The **Impact** stage is the fifth and final stage in the killchain pipeline:

```
Recon → Initial Access → Persistence → PrivEsc → **Impact**
```

**Purpose**: Achieve the operator's final objective — prove access, exfiltrate data, plant evidence, or demonstrate control. This is the "so what?" of the operation: tangible proof that the attack succeeded.

**Key differentiator**: This stage is **objective-driven** — the success criteria are derived from the operator's original attack objective, not from a fixed technical benchmark. The Planner interprets the objective and decides what actions constitute "mission accomplished."

---

## 2. Input Contract

The orchestrator calls `run_impact()` with data from all prior stages. Read `core_agents/orchestrator.py` lines 191–203 for the current stub.

```python
def run_impact(
    target_ip: str,
    objective: str,
    session_id: str,
    session_type: str,           # "command_shell" | "meterpreter"
    access_level: str,           # "user" | "root"
    prior_findings_summary: str, # Combined summary from recon + exploit + persist + privesc
    thread_id: str = None,
    recursion_limit: int = 80,
) -> ImpactFindings:
```

These values come from `PipelineState`:

| Field | Source |
|-------|--------|
| `target_ip` | `state["target_ip"]` |
| `objective` | `state["objective"]` |
| `session_id` | `state["exploitation_findings"]["session_id"]` |
| `session_type` | `state["exploitation_findings"]["session_type"]` |
| `access_level` | `state["privesc_findings"]["new_level"]` or `state["exploitation_findings"]["access_level"]` |
| `prior_findings_summary` | Built from all prior findings summaries |

---

## 3. Output Contract

Return an `ImpactFindings` TypedDict. Already defined in `core_agents/state.py`:

```python
class ImpactFindings(TypedDict):
    success: bool
    actions: list     # List of impact actions taken (strings)
    summary: str
```

---

## 4. Reference Files — READ THESE FIRST

| File | What to learn |
|------|---------------|
| `stages/recon.py` | Simpler 3-node graph (planner → executor → critic), ReAct loops, `build_graph()`, `run_recon()`, `main()` with `--graph` |
| `stages/initial_access.py` | Complex multi-node pattern, tool call counting, safety valves, `_extract_findings()`, `run_exploitation()` |
| `core_agents/state.py` | `ImpactFindings` TypedDict, `PipelineState` |
| `core_agents/common.py` | `Colors`, `print_colored`, `call_llm`, `parse_json_response`, `run_ssh_command`, `tool_linux_terminal`, config constants |
| `core_agents/orchestrator.py` | Stub at lines 191–203 to replace |
| `tools/rag.py` | `query_knowledge_base` signature |
| `tools/metasploit_tools.py` | `msf_session` object |

---

## 5. Architecture — Graph Flow

```
Planner ⟷ planner_tools → Executor ⟷ executor_tools → Critic
                                                          ↓
                                                   PASS → END
                                                   FAIL → Planner (max 3)
```

This is the simplest stage — just 3 LLM nodes, similar to `recon.py`.

### Nodes

| Node | LLM call? | Tools | Purpose |
|------|-----------|-------|---------|
| `planner` | Yes | `query_knowledge_base` (via `planner_tools`) | Interpret objective → list of impact actions |
| `planner_tools` | No | `ToolNode(PLANNER_TOOLS)` | Execute RAG queries |
| `executor` | Yes | `tool_linux_terminal`, `tool_metasploit_rpc` (via `executor_tools`) | Execute impact actions and collect proof |
| `executor_tools` | No | `ToolNode(EXECUTOR_TOOLS)` | Execute SSH/MSF commands |
| `critic` | Yes | None | Did we get concrete proof that the objective was met? |

### Edges

```
Entry → planner
planner → [planner_tools | executor]      # conditional: tool_calls → planner_tools, text → executor
planner_tools → planner                   # ReAct loop back
executor → [executor_tools | critic]      # conditional: tool_calls → executor_tools, text → critic
executor_tools → executor                 # ReAct loop back
critic → [planner | END]                  # conditional: FAIL → planner, PASS → END
```

---

## 6. Internal State TypedDict

```python
class ImpactState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    target_ip: str
    objective: str
    session_id: str
    session_type: str          # "command_shell" | "meterpreter"
    access_level: str          # "user" | "root"
    prior_findings: str        # Summary of prior stages
    impact_plan: str           # Planner's chosen actions
    impact_result: str         # Executor's summary + collected proof
    actions_taken: list        # List of action descriptions
    loop_step: int
    critic_verdict: str        # "PASS" | "FAIL"
```

---

## 7. Constants

```python
MAX_IMPACT_RETRIES = 3
MAX_PLANNER_TOOL_CALLS = 3
MAX_EXECUTOR_TOOL_CALLS = 10
```

---

## 8. Imports

```python
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
from core_agents.state import ImpactFindings
from tools.rag import query_knowledge_base
from tools.metasploit_tools import msf_session
```

---

## 9. Tool Definitions

```python
@tool
def tool_linux_terminal(command: str):
    """
    Execute a shell command on the Kali machine via SSH.
    Use this to execute impact actions through the active session:
    - Read sensitive files (shadow, passwd, configs)
    - Plant flag files as proof of access
    - Exfiltrate data back to Kali
    - Gather system intelligence

    NON-INTERACTIVE ONLY. No ftp, ssh, vi, nano, top.
    """
    if any(bad in command for bad in FORBIDDEN_COMMANDS):
        return "Command blocked by safety guardrails."
    print_colored(f"\n[Impact Terminal] Executing: {command}", Colors.OKCYAN)
    return run_ssh_command(command)


@tool
def tool_metasploit_rpc(command: str):
    """
    Execute a command on the active Metasploit console.
    Use for session interaction, file download/upload, hashdump.
    - 'sessions -i <id>' to interact with session
    - 'download <remote_path> <local_path>' (Meterpreter)
    - 'hashdump' (Meterpreter) for credential harvesting
    - 'run post/linux/gather/*' for intel gathering
    """
    try:
        return msf_session.send_command(command)
    except Exception as e:
        return f"RPC Error: {str(e)}"


# Tool sets
PLANNER_TOOLS = [query_knowledge_base]
EXECUTOR_TOOLS = [tool_linux_terminal, tool_metasploit_rpc]
```

---

## 10. System Prompts

### PLANNER_PROMPT

```python
PLANNER_PROMPT = f"""You are an Impact Planner for a Red Team agent. Your attacker IP is {KALI_IP}.

You receive:
1. OBJECTIVE — the operator's original attack goal
2. PRIOR FINDINGS — summary of recon, exploitation, persistence, privesc stages
3. SESSION INFO — active session details
4. ACCESS LEVEL — current privilege level
5. CRITIC FEEDBACK — if retrying, what was missing

**You have access to `query_knowledge_base`** — search for post-exploitation and data exfiltration techniques.
You may make up to {MAX_PLANNER_TOOL_CALLS} queries.

**Your job:** Interpret the objective and create a concrete impact action list that proves the objective was achieved.

**Standard impact actions (choose based on objective + access level):**

For "get a shell" / "gain access" objectives:
1. Run `whoami` and `id` — proof of access
2. Read `/etc/shadow` (if root) — proof of root
3. Create a flag file: `echo "COMPROMISED by Red Team $(date)" > /root/pwned.txt`
4. Gather system info: `hostname`, `ip addr`, `cat /etc/os-release`

For "exfiltrate data" objectives:
1. Locate target data (find files, read configs)
2. Copy data to Kali via netcat, scp, or Meterpreter download
3. Verify data received on Kali

For "demonstrate full control" objectives:
1. All of the above, plus:
2. List running services, installed software
3. Read SSH keys, application configs, database creds
4. Create proof bundle: system info + credentials + network info

**Output format (final answer — no more tool calls):**

IMPACT PLAN:
OBJECTIVE INTERPRETATION: <what "success" means for this specific objective>
ACTIONS:
1. <action description> — COMMAND: <exact command>
2. <action description> — COMMAND: <exact command>
...

SUCCESS CRITERIA: <what evidence proves the objective was met>

**On retry:**
- Read critic feedback
- Add missing proof actions
- Try alternative approaches to gather evidence
"""
```

### EXECUTOR_PROMPT

```python
EXECUTOR_PROMPT = f"""You are an Impact Executor for a Red Team agent. Your attacker IP is {KALI_IP}.

You have access to `tool_linux_terminal` (SSH to Kali) and `tool_metasploit_rpc` (MSF console).

**Your job:** Execute the impact plan and collect concrete proof.

**Rules:**
1. Execute commands ONE AT A TIME via tools
2. READ each output — this IS the proof
3. SAVE important outputs — they become evidence
4. Do NOT run more than {MAX_EXECUTOR_TOOL_CALLS} commands
5. When working through a session:
   - Meterpreter: `tool_metasploit_rpc` with 'sessions -i <id>'
   - Command shell: `tool_metasploit_rpc` with 'sessions -i <id>' then commands

**Key evidence-gathering commands:**

Access proof:
- `whoami` — current user
- `id` — UID/GID details
- `hostname` — system name
- `ip addr` or `ifconfig` — network config

Credential proof (root only):
- `cat /etc/shadow` — password hashes
- `cat /etc/passwd` — user accounts

Flag planting:
- `echo "COMPROMISED by Red Team $(date)" > /tmp/pwned.txt`
- `cat /tmp/pwned.txt` — verify flag was written

System intelligence:
- `uname -a` — kernel version
- `cat /etc/os-release` — OS details
- `df -h` — disk usage
- `last` — login history
- `cat /etc/ssh/sshd_config` — SSH config

**When done, provide a structured text summary of ALL evidence collected.**
Include the actual command outputs as proof.
Do not make any more tool calls after providing your summary.
"""
```

### CRITIC_PROMPT

```python
CRITIC_PROMPT = f"""You are an Impact Critic for a Red Team operation. Your IP is {KALI_IP}.

You evaluate whether the impact stage achieved the operator's objective with concrete proof.

**You receive:**
- The original objective
- The impact plan
- The execution result with collected evidence
- The loop step count

**Evaluation criteria:**

1. **Objective met?** — Does the evidence satisfy the operator's stated goal?
   - If objective was "get a shell": is there proof of command execution on target?
   - If objective was "exfil data": was data actually transferred to the attacker?
   - If objective was "prove root": is there output of `whoami` showing root?

2. **Concrete evidence?** — Are there actual command outputs (not just claims)?
   - `whoami` output = concrete
   - `/etc/shadow` contents = concrete
   - "I believe we have access" without proof = NOT concrete

3. **Flag planted?** — Was a proof file created on the target? (bonus, not required)

**Verdict:**
- **PASS** if: objective is substantially met with concrete evidence
- **FAIL** if: no concrete evidence, OR objective clearly not achieved

**Be lenient on the final attempt** — partial proof counts if the session is active.

**Output format:**

VERDICT: <PASS|FAIL>

EVIDENCE_QUALITY: <strong|moderate|weak>

ASSESSMENT: <2-3 sentence summary of what was proven>

FEEDBACK: <if FAIL — what specific evidence is still needed.
           Name exact commands to run for proof.>
"""
```

---

## 11. Node Implementations

### `planner_node`

```python
def planner_node(state: ImpactState) -> dict:
    """Interpret objective and plan impact actions. ReAct with RAG."""
    messages = state["messages"]
    print_colored("\n[Impact Planner] Planning impact actions...", Colors.HEADER)

    planner_tool_count = 0
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage):
            break
        if isinstance(msg, ToolMessage):
            planner_tool_count += 1

    if planner_tool_count == 0:
        context = (
            f"OBJECTIVE: {state.get('objective', '')}\n\n"
            f"TARGET: {state.get('target_ip', '')}\n"
            f"SESSION: {state.get('session_type', '')} (ID: {state.get('session_id', '')})\n"
            f"ACCESS LEVEL: {state.get('access_level', 'unknown')}\n\n"
            f"PRIOR FINDINGS SUMMARY:\n{state.get('prior_findings', '')}\n"
        )
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content:
                context += f"\nPREVIOUS FAILURE:\n{msg.content}\n"
                break
        planner_msgs = [HumanMessage(content=context)]
    else:
        cycle_start = 0
        for i in range(len(messages) - 1, -1, -1):
            if isinstance(messages[i], HumanMessage):
                cycle_start = i
                break
        planner_msgs = list(messages[cycle_start:])

    if planner_tool_count >= MAX_PLANNER_TOOL_CALLS:
        print_colored(f"[Impact Planner] RAG cap reached.", Colors.WARNING)
        response = call_llm(
            messages=planner_msgs + [HumanMessage(content="Max queries reached. Produce your impact plan now.")],
            system_prompt=PLANNER_PROMPT
        )
    else:
        response = call_llm(
            messages=planner_msgs,
            system_prompt=PLANNER_PROMPT,
            tools=PLANNER_TOOLS
        )

    if response.content and not response.tool_calls:
        print_colored(f"[Impact Planner] Plan:\n{response.content[:300]}", Colors.OKGREEN)

        # Extract action items from plan
        actions = []
        for line in response.content.split("\n"):
            line = line.strip()
            if re.match(r'^\d+\.', line):
                actions.append(line)

        return {
            "messages": [AIMessage(content=f"[Impact Planner] {response.content}")],
            "impact_plan": response.content,
            "actions_taken": actions,
        }

    return {"messages": [response]}
```

### `executor_node`

```python
def executor_node(state: ImpactState) -> dict:
    """Execute impact actions and collect proof. ReAct loop."""
    messages = state["messages"]
    print_colored("\n[Impact Executor] Executing impact actions...", Colors.HEADER)

    executor_tool_count = 0
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and "[Impact Planner]" in (msg.content or ""):
            break
        if isinstance(msg, ToolMessage):
            executor_tool_count += 1

    executor_msgs = []
    capturing = False
    for msg in messages:
        if isinstance(msg, AIMessage) and "[Impact Planner]" in (msg.content or ""):
            capturing = True
        if capturing:
            executor_msgs.append(msg)
    if not executor_msgs:
        executor_msgs = [messages[-1]]

    if executor_tool_count >= MAX_EXECUTOR_TOOL_CALLS:
        print_colored(f"[Impact Executor] Tool cap ({executor_tool_count}).", Colors.WARNING)
        response = call_llm(
            messages=executor_msgs + [HumanMessage(content=(
                "Max tool calls reached. Summarize all evidence collected so far."
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
        # Collect action summaries from executor
        actions = state.get("actions_taken", [])
        return {
            "messages": [response],
            "impact_result": response.content,
            "actions_taken": actions,
        }

    return {"messages": [response]}
```

### `critic_node`

```python
def critic_node(state: ImpactState) -> dict:
    """Evaluate whether objective was met with concrete proof."""
    current_step = state.get("loop_step", 0)
    print_colored("\n[Impact Critic] Evaluating evidence...", Colors.HEADER)

    evidence = (
        f"OBJECTIVE: {state.get('objective', '')}\n\n"
        f"IMPACT PLAN:\n{state.get('impact_plan', '')}\n\n"
        f"EXECUTION RESULT:\n{state.get('impact_result', '')}\n\n"
        f"ACCESS LEVEL: {state.get('access_level', 'unknown')}\n\n"
        f"LOOP STEP: {current_step} of {MAX_IMPACT_RETRIES}\n"
    )

    response = call_llm(
        messages=[HumanMessage(content=evidence)],
        system_prompt=CRITIC_PROMPT
    )

    verdict_text = response.content.strip()
    print_colored(f"[Impact Critic] {verdict_text[:300]}", Colors.OKCYAN)

    new_step = current_step + 1
    upper = verdict_text.upper()
    if "VERDICT: PASS" in upper or ("PASS" in upper and "FAIL" not in upper):
        verdict = "PASS"
    else:
        verdict = "FAIL"

    print_colored(f"[Impact Critic] Verdict: {verdict}",
                  Colors.OKGREEN if verdict == "PASS" else Colors.FAIL)

    if verdict == "PASS":
        return {
            "messages": [AIMessage(content=f"[Impact Critic] PASS — {verdict_text}")],
            "loop_step": new_step,
            "critic_verdict": "PASS",
        }
    else:
        return {
            "messages": [HumanMessage(content=f"CRITIC FEEDBACK: {verdict_text}")],
            "loop_step": new_step,
            "critic_verdict": "FAIL",
        }
```

### Tool Nodes

```python
def planner_tools_node(state: ImpactState) -> dict:
    tool_node = ToolNode(PLANNER_TOOLS)
    return tool_node.invoke(state)

def executor_tools_node(state: ImpactState) -> dict:
    tool_node = ToolNode(EXECUTOR_TOOLS)
    return tool_node.invoke(state)
```

---

## 12. Routing Logic

```python
def route_after_planner(state: ImpactState) -> Literal["planner_tools", "executor"]:
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        tool_count = 0
        for m in reversed(state["messages"]):
            if isinstance(m, HumanMessage):
                break
            if isinstance(m, ToolMessage):
                tool_count += 1
        if tool_count >= MAX_PLANNER_TOOL_CALLS:
            return "executor"
        return "planner_tools"
    return "executor"


def route_after_executor(state: ImpactState) -> Literal["executor_tools", "critic"]:
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        tool_count = 0
        for m in reversed(state["messages"]):
            if isinstance(m, AIMessage) and "[Impact Planner]" in (m.content or ""):
                break
            if isinstance(m, ToolMessage):
                tool_count += 1
        if tool_count >= MAX_EXECUTOR_TOOL_CALLS:
            return "critic"
        return "executor_tools"
    return "critic"


def route_after_critic(state: ImpactState) -> Literal["planner", "__end__"]:
    time.sleep(2)
    current_step = state.get("loop_step", 0)
    if current_step >= MAX_IMPACT_RETRIES:
        print_colored("--- MAX IMPACT RETRIES REACHED ---", Colors.FAIL)
        return END
    verdict = state.get("critic_verdict", "FAIL")
    if verdict == "PASS":
        return END
    return "planner"
```

---

## 13. Graph Construction — `build_graph()`

```python
def build_graph() -> StateGraph:
    workflow = StateGraph(ImpactState)

    workflow.add_node("planner", planner_node)
    workflow.add_node("planner_tools", planner_tools_node)
    workflow.add_node("executor", executor_node)
    workflow.add_node("executor_tools", executor_tools_node)
    workflow.add_node("critic", critic_node)

    workflow.set_entry_point("planner")

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

    # Critic routing
    workflow.add_conditional_edges(
        "critic", route_after_critic,
        {"planner": "planner", END: END}
    )

    return workflow
```

---

## 14. Findings Extraction — `_extract_impact_findings()`

```python
def _extract_impact_findings(state: dict) -> ImpactFindings:
    critic_verdict = state.get("critic_verdict", "")
    impact_plan = state.get("impact_plan", "")
    impact_result = state.get("impact_result", "")
    actions_taken = state.get("actions_taken", [])
    objective = state.get("objective", "")

    success = critic_verdict == "PASS"

    # Build actions list from actions_taken or parse from result
    if not actions_taken:
        # Try to extract from impact_result
        for line in (impact_result or "").split("\n"):
            line = line.strip()
            if line and (line.startswith("-") or re.match(r'^\d+\.', line)):
                actions_taken.append(line)

    # Ensure actions is a list of strings
    actions = [str(a) for a in actions_taken[:20]]  # Cap at 20

    if success:
        summary = f"Impact complete. Objective '{objective[:50]}' achieved. {len(actions)} actions taken."
    else:
        summary = f"Impact incomplete. Objective '{objective[:50]}' not fully proven. {impact_result[:100] if impact_result else ''}"

    return ImpactFindings(
        success=success,
        actions=actions,
        summary=summary,
    )
```

---

## 15. Entry Point — `run_impact()`

```python
def run_impact(
    target_ip: str,
    objective: str,
    session_id: str,
    session_type: str,
    access_level: str,
    prior_findings_summary: str = "",
    thread_id: str = None,
    recursion_limit: int = 80,
) -> ImpactFindings:
    import uuid

    if thread_id is None:
        thread_id = f"impact_{uuid.uuid4().hex[:8]}"

    workflow = build_graph()
    checkpointer = MemorySaver()
    app = workflow.compile(checkpointer=checkpointer)

    config = {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": recursion_limit,
    }

    initial_state = {
        "messages": [HumanMessage(content=(
            f"Execute impact actions for objective: {objective}\n"
            f"Target: {target_ip}\n"
            f"Session: {session_type} (ID: {session_id})\n"
            f"Access level: {access_level}"
        ))],
        "target_ip": target_ip,
        "objective": objective,
        "session_id": session_id,
        "session_type": session_type,
        "access_level": access_level,
        "prior_findings": prior_findings_summary,
        "impact_plan": "",
        "impact_result": "",
        "actions_taken": [],
        "loop_step": 0,
        "critic_verdict": "",
    }

    print_colored(f"\n{'='*60}", Colors.HEADER)
    print_colored(f"[run_impact] Starting impact subgraph", Colors.HEADER)
    print_colored(f"  Target: {target_ip}", Colors.HEADER)
    print_colored(f"  Objective: {objective[:80]}", Colors.HEADER)
    print_colored(f"  Session: {session_type} #{session_id}", Colors.HEADER)
    print_colored(f"  Access: {access_level}", Colors.HEADER)
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
                    if "[Impact Planner]" in content:
                        print_colored(f"\n{content[:400]}", Colors.OKBLUE)
                    elif "[Impact Critic]" in content:
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

    findings = _extract_impact_findings(final_state)

    print_colored(f"\n{'='*60}", Colors.HEADER)
    print_colored(
        f"[run_impact] Complete — success={findings['success']}",
        Colors.OKGREEN if findings["success"] else Colors.FAIL
    )
    print_colored(f"  {findings['summary']}", Colors.OKCYAN)
    print_colored(f"{'='*60}\n", Colors.HEADER)

    return findings
```

---

## 16. Orchestrator Integration

Replace the stub in `core_agents/orchestrator.py` (lines 191–203).

**Add import** at the top of `orchestrator.py`:
```python
from stages.impact import run_impact
```

**Replace `impact_stage_node`:**
```python
def impact_stage_node(state: PipelineState) -> dict:
    """Run the impact subgraph to prove the objective was achieved."""
    print_colored("\n[Pipeline] Running Impact stage...", Colors.HEADER)

    exploit = state.get("exploitation_findings", {})
    recon = state.get("recon_findings", {})
    persist = state.get("persistence_findings", {})
    privesc = state.get("privesc_findings", {})

    # Skip if no session
    if not exploit.get("success") or not exploit.get("session_id"):
        print_colored("[Pipeline] No active session — skipping impact.", Colors.WARNING)
        findings = {
            "success": False,
            "actions": [],
            "summary": "Impact skipped — no session available.",
        }
        return {
            "impact_findings": findings,
            "current_stage": "impact",
            "messages": [AIMessage(content="[Impact] Skipped — no active session.")],
        }

    # Build prior findings summary
    prior_summary = (
        f"Recon: {recon.get('summary', 'N/A')}\n"
        f"Exploitation: {exploit.get('summary', 'N/A')}\n"
        f"Persistence: {persist.get('summary', 'N/A')}\n"
        f"PrivEsc: {privesc.get('summary', 'N/A')}\n"
    )

    # Use escalated access level if available
    access_level = privesc.get("new_level", exploit.get("access_level", "unknown"))

    findings = run_impact(
        target_ip=exploit.get("target_ip", state["target_ip"]),
        objective=state["objective"],
        session_id=exploit["session_id"],
        session_type=exploit["session_type"],
        access_level=access_level,
        prior_findings_summary=prior_summary,
    )

    return {
        "impact_findings": dict(findings),
        "current_stage": "impact",
        "messages": [AIMessage(content=f"[Impact Complete] {findings['summary']}")],
    }
```

---

## 17. Standalone `main()`

```python
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

    print_colored("--- Impact Stage (Standalone) ---", Colors.OKGREEN)
    print_colored("Nodes: planner → executor → critic", Colors.OKCYAN)

    target_ip = input("\n[Target IP]: ").strip()
    objective = input("[Objective]: ").strip() or "Prove full access to the target system"
    session_id = input("[Session ID]: ").strip()
    session_type = input("[Session Type (command_shell/meterpreter)]: ").strip() or "command_shell"
    access_level = input("[Access Level (user/root)]: ").strip() or "root"

    findings = run_impact(
        target_ip=target_ip,
        objective=objective,
        session_id=session_id,
        session_type=session_type,
        access_level=access_level,
    )

    print("\n" + json.dumps(dict(findings), indent=2, default=str))


if __name__ == "__main__":
    main()
```

---

## 18. Module Docstring

```python
"""
Impact Subgraph — Execute final objective actions and collect proof of compromise.

Fifth and final stage of the killchain: recon → initial_access → persistence → privesc → **impact**.
Produces structured ImpactFindings for the pipeline critic.

Architecture:
    Planner ⟷ RAG → Executor ⟷ SSH/MSF → Critic
                                              ↓
                                       PASS → END
                                       FAIL → Planner (max 3)

Objective-driven: success criteria derived from the operator's original attack objective.

Usage:
    python stages/impact.py                 # Interactive standalone mode
    python stages/impact.py --graph         # Print graph topology
    from stages.impact import run_impact    # Programmatic subgraph call
"""
```

---

## 19. Verification Steps

```bash
# 1. Import test
python -c "from stages.impact import run_impact"

# 2. Graph topology
python stages/impact.py --graph

# 3. Standalone test (requires lab + active session)
python stages/impact.py

# 4. Integration: update orchestrator stub, run full pipeline
python -m core_agents.orchestrator
```

---

## 20. File Structure Summary

```
stages/impact.py
├── Module docstring
├── Imports (from core_agents.common, core_agents.state, tools.rag, tools.metasploit_tools)
├── Constants (MAX_IMPACT_RETRIES, MAX_*_TOOL_CALLS)
├── ImpactState TypedDict
├── Tool definitions (@tool wrappers)
├── Tool sets (PLANNER_TOOLS, EXECUTOR_TOOLS)
├── System prompts (PLANNER_PROMPT, EXECUTOR_PROMPT, CRITIC_PROMPT)
├── Node functions (planner_node, executor_node, critic_node)
├── Tool nodes (planner_tools_node, executor_tools_node)
├── Routing functions (route_after_planner/executor/critic)
├── build_graph()
├── _extract_impact_findings()
├── run_impact()
└── main() + if __name__ == "__main__"
```
