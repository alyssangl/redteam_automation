"""
Recon Subgraph — Autonomous nmap scanning with Planner → Executor → Critic loop.

First stage of the killchain: recon → exploitation → privesc → persistence → eval.
Produces structured ReconFindings for downstream consumption by run_exploitation().

Usage:
    python recon.py                          # Interactive standalone mode
    from recon import run_recon              # Programmatic subgraph call
"""

import re
import json
import operator
import time
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
from tools.rag import query_knowledge_base

# =============================================================================
# CONFIGURATION
# =============================================================================

dotenv.load_dotenv()

MODEL_NAME = "gpt-4o-mini"
KALI_IP = "192.168.34.6"
KALI_USER = "kali"
KALI_PASS = "kali"

MAX_RECON_RETRIES = 3
MAX_EXECUTOR_TOOL_CALLS = 10
MAX_PLANNER_TOOL_CALLS = 5

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
        stdin, stdout, stderr = ssh.exec_command(command, timeout=300)

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
# TOOLS
# =============================================================================

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


RECON_TOOLS = [tool_linux_terminal]
PLANNER_TOOLS = [query_knowledge_base]

# =============================================================================
# STATE DEFINITIONS
# =============================================================================

class ReconState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    plan: str               # Scan plan from orchestrator
    goal: str               # Overall objective from orchestrator
    scan_results: str       # Accumulated raw nmap output
    target_info: dict       # Parsed {ip, os, hostname, ports:[...]}
    loop_step: int
    critic_verdict: str     # "PASS" | "FAIL"


class ReconFindings(TypedDict):
    success: bool           # Did we get usable scan data?
    target_ip: str
    os_detected: str        # "Ubuntu Linux" | "Windows 10" | "unknown"
    hostname: str
    ports: list             # [{port, state, service, version}, ...]
    raw_nmap_output: str    # Full nmap output for exploitation subgraph
    target_info: dict       # Structured dict ready for run_exploitation()
    summary: str            # Brief text summary

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
# SYSTEM PROMPTS
# =============================================================================

PLANNER_PROMPT = f"""You are a Recon Planner for a Red Team agent. Your attacker IP is {KALI_IP}.

You receive:
1. SCAN PLAN — what to scan and how (from the orchestrator or default)
2. GOAL — overall operator objective
3. CRITIC FEEDBACK — if retrying, what was missing from the previous scan

Your job: produce a numbered sequence of nmap commands to execute on the target.

**You have access to `query_knowledge_base`** — a RAG tool that searches your internal knowledge base of
penetration testing techniques, nmap strategies, and service-specific recon approaches.

**Before producing your command list, query the knowledge base** for relevant techniques:
- Search for nmap scanning strategies relevant to the target or goal
- Search for service-specific recon techniques if the goal mentions particular services
- Use verbose, descriptive queries (e.g., "nmap techniques for discovering hidden services and UDP ports on Linux targets")
- You may make up to {MAX_PLANNER_TOOL_CALLS} knowledge base queries
- Once you have enough information, stop querying and produce your final command list (no more tool calls)

**Strategy — use a two-phase approach:**

Phase 1: Quick discovery scan
- `nmap -sS -T4 -p- <target>` (full port SYN scan, fast timing)
- OR `nmap -sS -T4 --top-ports 1000 <target>` if time is limited

Phase 2: Deep scan on discovered ports
- `nmap -sV -sC -O -p<port1,port2,...> <target>` (version detection, default scripts, OS detection)
- Only scan ports found open in Phase 1

**On retry (critic feedback present):**
- Read the critic's feedback carefully
- Query the knowledge base for techniques to address specific gaps
- If no version info: add `-sV` flag
- If no OS info: add `-O` or `-A` flag
- If no ports found: try `-Pn` (skip host discovery) or UDP scan `-sU --top-ports 50`
- If scan errored: adjust timing (`-T3`) or try a different scan type

**Output format (final answer — no tool calls):**
Provide a numbered list of nmap commands, one per line. Include brief comments explaining each phase.

Example:
1. nmap -sS -T4 --top-ports 1000 192.168.34.7  # Phase 1: Quick SYN scan
2. nmap -sV -sC -O -p22,80,445 192.168.34.7    # Phase 2: Deep scan on discovered ports
"""

EXECUTOR_PROMPT = f"""You are a Recon Execution Specialist. Your attacker IP is {KALI_IP}.

You have access to `tool_linux_terminal` to run commands on the Kali machine.

**Rules:**
1. Execute the nmap commands from the plan ONE AT A TIME via `tool_linux_terminal`
2. READ each command's output carefully before running the next
3. ADAPT between phases: if Phase 1 finds open ports, use those specific ports in Phase 2
4. If a scan returns no results or errors, try adjusting (e.g., add `-Pn`, change timing)
5. Do NOT run more than {MAX_EXECUTOR_TOOL_CALLS} commands total

**When done scanning, provide a TEXT SUMMARY of all findings:**
- List all open ports with service names and versions
- Note any OS detection results
- Note any interesting scripts output (e.g., anonymous FTP, SMB shares)
- Include the target IP

**Important:**
- nmap scans can take time — this is normal, be patient
- If a full port scan is too slow, fall back to top-ports scan
- Always use `sudo` with nmap for SYN scans (`sudo nmap -sS ...`)
"""

CRITIC_PROMPT = f"""You are a Recon Quality Assessor for a Red Team operation. Your IP is {KALI_IP}.

You evaluate whether the reconnaissance scan gathered sufficient data for the exploitation phase.

**You receive:**
- The executor's scan summary and raw nmap outputs
- The original scan plan and goal

**Evaluation criteria:**

1. **Open ports found?** — At least 1 open port must be identified
2. **Service versions?** — Services should have version strings (e.g., "OpenSSH 7.9p1", "Apache 2.4.38")
3. **OS detection?** — OS guess should be present (even approximate is acceptable)
4. **Scan completeness?** — Were both quick and deep scans performed?

**Verdict:**
- **PASS** if: at least 1 open port with service AND version identified. OS detection is preferred but not required for PASS.
- **FAIL** if: no open ports found, OR ports found but NO version info on any service, OR scan errored out completely

**Output format:**

VERDICT: <PASS|FAIL>

FINDINGS_QUALITY: <brief assessment of what was found>

MISSING: <what specific data is missing, if any>

FEEDBACK: <specific instructions for retry if FAIL — e.g., "Rescan with -sV to get version info on ports 22,80,443">

**When PASS, also output a structured JSON block with the parsed target info:**

TARGET_INFO:
{{"ip": "<target IP>", "os": "<detected OS or unknown>", "hostname": "<hostname or unknown>", "ports": [{{"port": <int>, "state": "open", "service": "<name>", "version": "<version string>"}}]}}

Rules for TARGET_INFO JSON:
- Only include ports with state "open"
- If version is unknown, use empty string ""
- Extract OS from nmap OS guesses or service banners
- Do NOT include your own IP ({KALI_IP}) as the target
"""

# =============================================================================
# GRAPH NODES
# =============================================================================

def planner_node(state: ReconState) -> dict:
    """Decide nmap scan strategy based on plan, goal, and any critic feedback. ReAct loop with RAG."""
    plan = state.get("plan", "")
    goal = state.get("goal", "")
    messages = state["messages"]

    print_colored("\n[Recon Planner] Designing scan strategy...", Colors.HEADER)

    # Count planner tool calls already made in this cycle
    planner_tool_count = 0
    for msg in reversed(messages):
        # Stop counting at cycle boundary: critic feedback or the initial human message
        if isinstance(msg, HumanMessage):
            break
        if isinstance(msg, ToolMessage):
            planner_tool_count += 1

    # Build planner message window from cycle start
    planner_msgs = []
    # Find the start of the current planner cycle (critic feedback or beginning)
    cycle_start_idx = 0
    for i in range(len(messages) - 1, -1, -1):
        if isinstance(messages[i], HumanMessage):
            cycle_start_idx = i
            break

    # If this is the first call (no prior tool calls), build the context message
    if planner_tool_count == 0:
        context = f"SCAN PLAN:\n{plan}\n\n"
        context += f"GOAL:\n{goal}\n\n"

        # Include critic feedback if retrying
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage) and "CRITIC FEEDBACK" in msg.content:
                context += f"PREVIOUS SCAN FEEDBACK:\n{msg.content}\n\n"
                break

        # Include prior scan results if retrying so planner knows what was already tried
        scan_results = state.get("scan_results", "")
        if scan_results:
            truncated = scan_results[-3000:] if len(scan_results) > 3000 else scan_results
            context += f"PREVIOUS SCAN RESULTS (for reference):\n{truncated}\n\n"

        planner_msgs = [HumanMessage(content=context)]
    else:
        # Continuing a ReAct loop — include messages from cycle start
        planner_msgs = list(messages[cycle_start_idx:])

    # Safety valve: if too many tool calls, force text output
    if planner_tool_count >= MAX_PLANNER_TOOL_CALLS:
        print_colored(
            f"[Recon Planner] Safety valve: {planner_tool_count} RAG queries reached.",
            Colors.WARNING
        )
        response = call_llm(
            messages=planner_msgs + [HumanMessage(content=(
                "You have used your maximum knowledge base queries. Now produce your final "
                "numbered list of nmap commands based on what you learned."
            ))],
            system_prompt=PLANNER_PROMPT
        )
    else:
        response = call_llm(
            messages=planner_msgs,
            system_prompt=PLANNER_PROMPT,
            tools=PLANNER_TOOLS
        )

    # Tag the final text response with [Recon Planner] prefix if it's a text answer
    if response.content and not response.tool_calls:
        print_colored(f"[Recon Planner] Strategy:\n{response.content[:400]}", Colors.OKGREEN)
        return {
            "messages": [AIMessage(content=f"[Recon Planner] {response.content}")]
        }

    return {"messages": [response]}


def executor_node(state: ReconState) -> dict:
    """Execute nmap commands one at a time via tool_linux_terminal. ReAct loop."""
    messages = state["messages"]

    print_colored("\n[Recon Executor] Running scan commands...", Colors.HEADER)

    # Count tool calls already made in this executor cycle
    executor_tool_count = 0
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and "[Recon Planner]" in (msg.content or ""):
            break
        if isinstance(msg, ToolMessage):
            executor_tool_count += 1

    # Build executor message window: from planner output onwards
    executor_msgs = []
    capturing = False
    for msg in messages:
        if isinstance(msg, AIMessage) and "[Recon Planner]" in (msg.content or ""):
            capturing = True
        if capturing:
            executor_msgs.append(msg)

    if not executor_msgs:
        executor_msgs = [messages[-1]]

    # Safety valve: force text summary if too many tool calls
    if executor_tool_count >= MAX_EXECUTOR_TOOL_CALLS:
        print_colored(
            f"[Recon Executor] Safety valve: {executor_tool_count} tool calls reached.",
            Colors.WARNING
        )
        response = call_llm(
            messages=executor_msgs + [HumanMessage(content=(
                "You have used your maximum tool calls. Provide a text summary of all "
                "scan results so far. List all open ports, services, versions, and OS info discovered."
            ))],
            system_prompt=EXECUTOR_PROMPT
        )
    else:
        response = call_llm(
            messages=executor_msgs,
            system_prompt=EXECUTOR_PROMPT,
            tools=RECON_TOOLS
        )

    return {"messages": [response]}


def executor_tools_node(state: ReconState) -> dict:
    """Execute tool calls from the executor and accumulate scan results."""
    tool_node = ToolNode(RECON_TOOLS)
    result = tool_node.invoke(state)

    # Accumulate raw nmap output into scan_results
    new_output = ""
    if "messages" in result:
        for msg in result["messages"]:
            if isinstance(msg, ToolMessage) and msg.content:
                new_output += msg.content + "\n\n"

    existing = state.get("scan_results", "") or ""
    return {
        **result,
        "scan_results": existing + new_output
    }


def critic_node(state: ReconState) -> dict:
    """Evaluate scan completeness and extract target_info on PASS."""
    messages = state["messages"]
    scan_results = state.get("scan_results", "")
    plan = state.get("plan", "")
    goal = state.get("goal", "")
    current_step = state.get("loop_step", 0)

    print_colored("\n[Recon Critic] Evaluating scan quality...", Colors.HEADER)

    # Get executor's text summary (last non-tool AI message)
    executor_summary = ""
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and not msg.tool_calls and msg.content:
            executor_summary = msg.content
            break

    # Truncate scan_results for the critic to avoid overloading
    truncated_results = scan_results[-6000:] if len(scan_results) > 6000 else scan_results

    evidence = (
        f"SCAN PLAN:\n{plan}\n\n"
        f"GOAL:\n{goal}\n\n"
        f"EXECUTOR SUMMARY:\n{executor_summary}\n\n"
        f"RAW SCAN OUTPUT (recent):\n{truncated_results}\n\n"
        f"LOOP STEP: {current_step} of {MAX_RECON_RETRIES}\n"
    )

    response = call_llm(
        messages=[HumanMessage(content=evidence)],
        system_prompt=CRITIC_PROMPT
    )

    verdict_text = response.content.strip()
    print_colored(f"[Recon Critic] {verdict_text[:300]}", Colors.OKCYAN)

    new_step = current_step + 1

    # Extract verdict
    upper = verdict_text.upper()
    if "VERDICT: PASS" in upper or ("PASS" in upper and "FAIL" not in upper):
        verdict = "PASS"
    else:
        verdict = "FAIL"

    print_colored(f"[Recon Critic] Verdict: {verdict}", Colors.OKGREEN if verdict == "PASS" else Colors.FAIL)

    if verdict == "PASS":
        # Extract target_info JSON from critic response
        target_info = parse_json_response(verdict_text)
        if not target_info or "ip" not in target_info:
            # Try extracting from TARGET_INFO: block
            ti_match = re.search(r'TARGET_INFO:\s*(\{.*?\})', verdict_text, re.DOTALL)
            if ti_match:
                target_info = parse_json_response(ti_match.group(1))

        # Fallback: basic extraction from scan_results
        if not target_info or "ip" not in target_info:
            target_info = _fallback_parse_target_info(scan_results)

        return {
            "messages": [AIMessage(content=f"[Recon Critic] PASS — {verdict_text}")],
            "loop_step": new_step,
            "critic_verdict": "PASS",
            "target_info": target_info
        }
    else:
        return {
            "messages": [HumanMessage(content=f"CRITIC FEEDBACK: {verdict_text}")],
            "loop_step": new_step,
            "critic_verdict": "FAIL"
        }


def _fallback_parse_target_info(scan_results: str) -> dict:
    """Best-effort extraction of target info from raw nmap output."""
    # Extract IP (skip our own)
    all_ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', scan_results)
    target_ip = "unknown"
    for ip in all_ips:
        if ip != KALI_IP and not ip.startswith("127."):
            target_ip = ip
            break

    # Extract open ports
    ports = []
    # Match nmap output lines like: 22/tcp   open  ssh     OpenSSH 7.9p1
    port_pattern = re.compile(
        r'(\d+)/(?:tcp|udp)\s+open\s+(\S+)\s*(.*)', re.MULTILINE
    )
    for match in port_pattern.finditer(scan_results):
        port_num = int(match.group(1))
        service = match.group(2)
        version = match.group(3).strip()
        ports.append({
            "port": port_num,
            "state": "open",
            "service": service,
            "version": version
        })

    # Extract OS
    os_detected = "unknown"
    os_match = re.search(r'OS details?:\s*(.+)', scan_results)
    if os_match:
        os_detected = os_match.group(1).strip()
    else:
        os_match = re.search(r'Running:\s*(.+)', scan_results)
        if os_match:
            os_detected = os_match.group(1).strip()

    # Extract hostname
    hostname = "unknown"
    host_match = re.search(r'Nmap scan report for (\S+)', scan_results)
    if host_match:
        val = host_match.group(1)
        # If it's just an IP, check for hostname in parentheses
        paren_match = re.search(r'Nmap scan report for (\S+) \((\S+)\)', scan_results)
        if paren_match:
            hostname = paren_match.group(1)
        elif not re.match(r'\d+\.\d+\.\d+\.\d+', val):
            hostname = val

    return {
        "ip": target_ip,
        "os": os_detected,
        "hostname": hostname,
        "ports": ports
    }

# =============================================================================
# ROUTING FUNCTIONS
# =============================================================================

def planner_tools_node(state: ReconState) -> dict:
    """Execute RAG tool calls from the planner."""
    tool_node = ToolNode(PLANNER_TOOLS)
    return tool_node.invoke(state)


def route_after_planner(state: ReconState) -> Literal["planner_tools", "executor"]:
    """Route planner output: tool call -> planner_tools, text -> executor."""
    last_msg = state["messages"][-1]

    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        # Check safety valve
        planner_tool_count = 0
        for msg in reversed(state["messages"]):
            if isinstance(msg, HumanMessage):
                break
            if isinstance(msg, ToolMessage):
                planner_tool_count += 1

        if planner_tool_count >= MAX_PLANNER_TOOL_CALLS:
            return "executor"

        return "planner_tools"
    return "executor"


def route_after_executor(state: ReconState) -> Literal["executor_tools", "critic"]:
    """Route executor output: tool call -> tools node, text -> critic."""
    last_msg = state["messages"][-1]

    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        # Check safety valve
        executor_tool_count = 0
        for msg in reversed(state["messages"]):
            if isinstance(msg, AIMessage) and "[Recon Planner]" in (msg.content or ""):
                break
            if isinstance(msg, ToolMessage):
                executor_tool_count += 1

        if executor_tool_count >= MAX_EXECUTOR_TOOL_CALLS:
            return "critic"

        return "executor_tools"
    return "critic"


def route_after_critic(state: ReconState) -> Literal["planner", "__end__"]:
    """Route based on critic verdict: PASS -> END, FAIL -> planner for retry."""
    time.sleep(2)  # Rate limiting

    current_step = state.get("loop_step", 0)
    if current_step >= MAX_RECON_RETRIES:
        print_colored("--- MAX RECON RETRIES REACHED ---", Colors.FAIL)
        return END

    verdict = state.get("critic_verdict", "FAIL")

    if verdict == "PASS":
        return END
    else:
        return "planner"

# =============================================================================
# GRAPH CONSTRUCTION
# =============================================================================

def build_graph() -> StateGraph:
    """Construct the recon subgraph: planner -> executor <-> tools -> critic."""
    workflow = StateGraph(ReconState)

    # Add nodes
    workflow.add_node("planner", planner_node)
    workflow.add_node("planner_tools", planner_tools_node)
    workflow.add_node("executor", executor_node)
    workflow.add_node("executor_tools", executor_tools_node)
    workflow.add_node("critic", critic_node)

    # Entry point
    workflow.set_entry_point("planner")

    # Planner ReAct loop
    workflow.add_conditional_edges(
        "planner",
        route_after_planner,
        {"planner_tools": "planner_tools", "executor": "executor"}
    )
    workflow.add_edge("planner_tools", "planner")

    # Executor ReAct loop
    workflow.add_conditional_edges(
        "executor",
        route_after_executor,
        {"executor_tools": "executor_tools", "critic": "critic"}
    )
    workflow.add_edge("executor_tools", "executor")

    # Critic routing
    workflow.add_conditional_edges(
        "critic",
        route_after_critic,
        {"planner": "planner", END: END}
    )

    return workflow

# =============================================================================
# OUTPUT EXTRACTION
# =============================================================================

def _extract_recon_findings(state: dict) -> ReconFindings:
    """Build structured ReconFindings from final graph state."""
    target_info = state.get("target_info", {})
    scan_results = state.get("scan_results", "")
    critic_verdict = state.get("critic_verdict", "")
    messages = state.get("messages", [])

    success = critic_verdict == "PASS"

    # If critic didn't produce target_info, fallback parse
    if not target_info or "ip" not in target_info:
        target_info = _fallback_parse_target_info(scan_results)

    target_ip = target_info.get("ip", "unknown")
    os_detected = target_info.get("os", "unknown")
    hostname = target_info.get("hostname", "unknown")
    ports = target_info.get("ports", [])

    # Build summary
    if success and ports:
        port_list = ", ".join(
            f"{p['port']}/{p.get('service', '?')}" for p in ports[:10]
        )
        summary = (
            f"Recon complete on {target_ip} ({os_detected}). "
            f"{len(ports)} open port(s): {port_list}"
        )
    elif ports:
        summary = f"Partial recon on {target_ip}. {len(ports)} port(s) found but scan incomplete."
    else:
        summary = f"Recon failed on {target_ip}. No open ports discovered."

    return ReconFindings(
        success=success,
        target_ip=target_ip,
        os_detected=os_detected,
        hostname=hostname,
        ports=ports,
        raw_nmap_output=scan_results,
        target_info=target_info,
        summary=summary,
    )

# =============================================================================
# SUBGRAPH WRAPPER
# =============================================================================

def run_recon(
    target_ip: str,
    goal: str = "",
    plan: str = "",
    thread_id: str = None,
    recursion_limit: int = 50,
) -> ReconFindings:
    """Run the recon graph as a callable subgraph and return structured findings.

    Args:
        target_ip: IP address of the target to scan.
        goal: Overall objective (e.g., "enumerate all services").
        plan: Specific scan plan. If empty, a default is generated.
        thread_id: Optional thread ID for checkpointing.
        recursion_limit: Max LangGraph recursion steps.

    Returns:
        ReconFindings dict with success, ports, OS, raw output, etc.
    """
    import uuid

    if thread_id is None:
        thread_id = f"recon_{uuid.uuid4().hex[:8]}"

    if not plan:
        plan = f"Perform comprehensive nmap scan of {target_ip}. Discover all open ports, service versions, and OS information."

    if not goal:
        goal = f"Enumerate all services and versions on {target_ip}"

    workflow = build_graph()
    checkpointer = MemorySaver()
    app = workflow.compile(checkpointer=checkpointer)

    config = {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": recursion_limit,
    }

    initial_state = {
        "messages": [HumanMessage(content=f"Scan target: {target_ip}\nGoal: {goal}\nPlan: {plan}")],
        "plan": plan,
        "goal": goal,
        "scan_results": "",
        "target_info": {},
        "loop_step": 0,
        "critic_verdict": "",
    }

    print_colored(f"\n{'='*60}", Colors.HEADER)
    print_colored(f"[run_recon] Starting recon subgraph", Colors.HEADER)
    print_colored(f"  Target: {target_ip}", Colors.HEADER)
    print_colored(f"  Goal: {goal[:100]}", Colors.HEADER)
    print_colored(f"  Thread: {thread_id}", Colors.HEADER)
    print_colored(f"{'='*60}\n", Colors.HEADER)

    # Stream to completion with progress printing
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
                elif isinstance(msg, ToolMessage):
                    display = msg.content[:500]
                    if len(msg.content) > 500:
                        display += "... [truncated]"
                    print(f"\n[Tool Output]: {display}")
                elif isinstance(msg, AIMessage):
                    content = msg.content
                    if content.startswith("[Recon Planner]"):
                        print_colored(f"\n{content}", Colors.OKBLUE)
                    elif content.startswith("[Recon Critic]"):
                        color = Colors.OKGREEN if "PASS" in content else Colors.FAIL
                        print_colored(f"\n{content[:500]}", color)
                    elif content.startswith("[Recon Executor]"):
                        print_colored(f"\n{content}", Colors.WARNING)
                    else:
                        print_colored(f"\nAgent: {content}", Colors.OKGREEN)

                # Show tool calls being made
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    for t in msg.tool_calls:
                        print_colored(
                            f"   (Calling Tool: {t['name']} args: {str(t['args'])[:200]}...)",
                            Colors.OKCYAN
                        )

    # Extract final state and return structured findings
    final_state_snapshot = app.get_state(config)
    final_state = final_state_snapshot.values

    findings = _extract_recon_findings(final_state)

    print_colored(f"\n{'='*60}", Colors.HEADER)
    print_colored(
        f"[run_recon] Complete — success={findings['success']}",
        Colors.OKGREEN if findings["success"] else Colors.FAIL
    )
    print_colored(f"  {findings['summary']}", Colors.OKCYAN)
    print_colored(f"{'='*60}\n", Colors.HEADER)

    return findings

# =============================================================================
# STANDALONE MODE
# =============================================================================

def main():
    """Interactive standalone mode: python recon.py"""

    # Handle --graph flag for visualization
    if "--graph" in __import__("sys").argv:
        workflow = build_graph()
        app = workflow.compile()
        try:
            print(app.get_graph().draw_ascii())
        except Exception:
            graph = app.get_graph()
            print("Nodes:", [n for n in graph.nodes])
            print("Edges:", [(e.source, e.target) for e in graph.edges])
        return

    print_colored("--- Recon Subgraph (Autonomous nmap Scanner) ---", Colors.OKGREEN)
    print_colored("Nodes: planner -> executor <-> tools -> critic", Colors.OKCYAN)

    target_ip = input("\n[Target IP]: ").strip()
    if not target_ip:
        print_colored("No target IP provided. Exiting.", Colors.FAIL)
        return

    goal = input("[Goal (optional, press Enter to skip)]: ").strip()

    findings = run_recon(target_ip=target_ip, goal=goal)

    print("\n" + json.dumps(findings, indent=2, default=str))


if __name__ == "__main__":
    main()
