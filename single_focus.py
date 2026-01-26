import os
import sys
import operator
import time

import dotenv
from typing import TypedDict, Annotated, List, Literal
from metasploit_tools import *

import paramiko
from langchain_openai import ChatOpenAI
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver

# Assuming rag.py exists in your directory as implied by your import
from rag import query_knowledge_base

import atexit
from pymetasploit3.msfrpc import MsfRpcClient


dotenv.load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

MODEL_NAME = "gpt-4o"
KALI_IP = "192.168.34.6"
KALI_USER = "kali"
KALI_PASS = "kali"
MSF_PORT = 55553
MSF_USER = 'kali'
MSF_PASS = 'kali'
MAX_RETRIES = 10


# --- 1. EXISTING SSH HELPER (UNCHANGED) ---
def _run_ssh_command(command_str, description):
    """Helper to run SSH commands silently (no streaming print)"""
    # Removed the "Connecting..." print to reduce noise
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=10)

        stdin, stdout, stderr = ssh.exec_command(command_str)
        output_buffer = []

        # Stream output to buffer ONLY, do not print to console
        for line in iter(stdout.readline, ""):
            output_buffer.append(line)

        err_output = stderr.read().decode()

        # Only print stderr if it exists and is critical (optional, usually safer to capture)
        # if err_output:
        #     print(f"\n[Remote STDERR]: {err_output}")

        exit_status = stdout.channel.recv_exit_status()
        full_log = "".join(output_buffer).strip()

        if exit_status == 0:
            if not full_log:
                return (f"Command '{command_str}' executed successfully but returned NO OUTPUT.\n"
                        f"CRITICAL: You must receive output to verify results.\n"
                        f"REACTION REQUIRED: Check log files or use verbose flags.")
            return f"Command '{command_str}' succeeded.\nOutput:\n{full_log}"
        else:
            return f"Command '{command_str}' failed (Exit Code: {exit_status}).\nError:\n{err_output}"

    except Exception as e:
        return f"SSH Connection/Execution Error: {str(e)}"
    finally:
        ssh.close()


@tool
def tool_metasploit_rpc(command: str):
    """
    Executes a command on the ACTIVE Metasploit console.
    State is preserved. You can run 'use exploit/...' in one turn,
    and 'set RHOST ...' in the next.
    **METASPLOIT USAGE**: You have a persistent console session open.
    1. You do NOT need to chain commands. You can issue 'use exploit/...' then wait for the result.
    2. If a command fails (e.g. 'Unknown command'), check your spelling or context.
    **CRITICAL** 3. When ready to attack YOU MUST ALWAYS FIRST use 'show options' to verify that all the fields are set correctly.
    4. If you ran the 'show options' and VERY VERY VERY VERY SURE THAT THE OPTIONS ARE SET, you can finally run the exploit by using 'run -z' (run in background) or just 'run'.
    4. ALWAYS check the output. If it says 'Exploit completed, but no session', it FAILED. Try a different payload or target.
    """
    try:
        return msf_session.send_command(command)
    except Exception as e:
        return f"RPC Error: {str(e)}"


@tool
def tool_linux_terminal(command: str):
    """Executes a command on the remote Linux (Kali) terminal via SSH."""
    forbidden = ["rm -rf /", ":(){ :|:& };:"]
    if any(bad in command for bad in forbidden):
        return "Command blocked by safety guardrails."
    print(f"\n[Terminal Tool] Executing: {command}")
    return _run_ssh_command(command, "Linux Terminal")


# --- 2. UPDATED STATE & TOOLS ---

class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    loop_step: int


tools = [query_knowledge_base, tool_linux_terminal, tool_metasploit_rpc]


# --- 3. NODE DEFINITIONS ---

def llm_node(state: AgentState):
    """The Worker: Generates attacks or runs tools."""
    messages = state['messages']

    # Check if we have critique feedback from the previous loop
    # If the last message was from the Critic (AI), we treat it as instructions

    sys_msg = SystemMessage(
        content=(
            f"You are a Red Team Initial Access Phase Agent running on {MODEL_NAME}. Your IP address is {KALI_IP}\n"
            "**FORMATTING RULE**: Before every tool call, output a 'Thought:' line explaining your strategy.\n\n"
            "**OPERATIONAL WORKFLOW:**\n\n"
            "1. **STRATEGIC ANALYSIS**:\n"
            "   - Analyze the user's objective.\n"
            "   - **AUTOMATICALLY SELECT** the most appropriate Atomic Red Team Technique ID.\n\n"
            "2. **INTELLIGENCE PHASE (Mandatory)**:\n"
            "   - **Goal-Oriented Retrieval**: You MUST search the knowledge base to find specific, executable commands that achieve your current objective.\n"
            "   - **Platform Awareness**: If the user targets a specific OS (e.g., Linux), YOU MUST use the 'platform' parameter in the tool.\n\n"
            "3. **ADAPTATION PHASE (Smart & Flexible)**:\n"
            "   - **Intelligent Parameter Selection**: You are an expert. The RAG results provide the *method* (exploit module), but you must determine the correct *values*.\n"
            "   - **Mandatory Updates**: Always overwrite RAG example IPs/Ports with the User's Target.\n"
            "   - **Contextual Filling**: If a module requires an option (e.g., SITEPATH, TARGETURI) and the RAG example is ambiguous or missing it, USE YOUR GENERAL KNOWLEDGE to select standard defaults.\n"
            "   - **Universal Parameters**: ALWAYS run `set RHOSTS <target>`, `set LHOST {KALI_IP}`, `set LPORT 4444`.\n\n"
            "4. **EXECUTION PHASE**:\n"
            "   - Execute the configured command.\n"
            "   - If RAG was empty, select a generic alternative (but still configure IPs correctly).\n\n"
            "5. **REPORTING**:\n"
            "   - Report success/failure.\n"
            "   - If success, report your findings.\n"
            "   - If fails, conclude what might be the cause of the failure."
        )
    )

    model = ChatOpenAI(model=MODEL_NAME, temperature=0)
    model_with_tools = model.bind_tools(tools)
    response = model_with_tools.invoke([sys_msg] + messages)

    # Reset loop count if we are just starting or responding to a user
    current_step = state.get("loop_step", 0)
    return {"messages": [response], "loop_step": current_step + 1}

def critic_node(state: AgentState):
    """The Critic: Reviews the Worker's execution."""
    messages = state['messages']

    # Get the last message (The Agent's final report/response)
    last_message = messages[-1]

    # --- FIX START: ROBUST CONTEXT EXTRACTION ---
    # We need to find if the Agent ran a tool in this "turn".
    # A "turn" might include: [AI Call] -> [Tool Output] -> [AI Report]

    has_tool_execution = False
    tool_outputs = ""

    # Scan backwards to find the last AI 'report' and the tool outputs preceding it
    # We look at the last 3 messages to find evidence of work
    search_window = messages[-3:]

    for msg in search_window:
        if isinstance(msg, ToolMessage):
            has_tool_execution = True
            # Capture the output
            tool_outputs += f"\n[Tool Output]: {msg.content[:500]}..."

            # If the last message itself HAS tool_calls (unlikely if we are in critic node, but safe to check)
    if last_message.tool_calls:
        has_tool_execution = True
    # --- FIX END ---

    # 3. Construct the Critique Prompt
    critic_model = ChatOpenAI(model=MODEL_NAME, temperature=0)

    context_block = f"""
        [EVIDENCE OF EXECUTION]
        Tool Ran: {has_tool_execution}
        Tool Output (Snippet): {tool_outputs[:500]}...
        """

    system_prompt = f"""You are a Senior Red Team Lead. 
        Review the Agent's performance based on the EVIDENCE provided.
        Your IP address is {KALI_IP}

        **JUDGMENT RULES:**
        1. **PERSISTENCE CHECK (Crucial)**:
           - Did the Agent try ONE thing, fail, and immediately give up? -> **FAIL**.
           - If the tool output said "Exploit failed" or "Target not vulnerable", did the Agent try a DIFFERENT exploit, port, or service? 
           - If they just said "I failed, what next?", that is **LAZY**. They must try at least 2-3 alternatives (e.g. different payloads, different services) before giving up.

        2. **INTENT CHECK**:
           - If the User's goal did NOT require a tool (e.g. "What is this?", "Hello"), then No Tool is **PASS**.
           - If the User's goal WAS an attack (e.g. "Get a shell", "Scan"), and 'Tool Ran' is False -> **FAIL**.

        3. **EXECUTION CHECK**:
           - If the output shows a user error (e.g. forgot LHOST, bad path), that is a **FAIL** (instruct them to fix parameters).
           - If the output shows a system error (e.g. 'Connection refused'), that is a **PASS** on execution, but check Rule #1 (Did they try an alternative?).
        4. **Laziness**:
        - Laziness is defined as encountering a FIXABLE error (like a bad path, missing option, or wrong port) and immediately giving up or switching services without trying to debug the current exploit.
        - True persistence means reading the error message, adjusting the parameter (e.g., SITEPATH, LHOST), and retrying.

        **OUTPUT FORMAT:**
        - If satisfied (Agent tried hard, or error was unfixable): "PASS"
        - If lazy (gave up on a fixable error): "FAIL: [Specific Instruction, e.g. 'The error said directory not writable. Try changing SITEPATH to /tmp or /var/www and retry the SAME exploit.']"
        """

    critique_response = critic_model.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(
            content=f"{context_block}\n\nUser Goal: {messages[0].content}\nAgent Report: {last_message.content}")
    ])

    content = critique_response.content
    print(f"\n[Critic] Review: {content}")

    if "FAIL" in content:
        return {"messages": [HumanMessage(content=f"SENIOR LEAD FEEDBACK: {content}")]}

    return {"messages": []}

# --- 4. CONDITIONAL EDGES ---

def check_reflection(state: AgentState) -> Literal["tools", "critic", END]:
    """Decides where to go next based on the Worker's output."""
    messages = state['messages']
    last_msg = messages[-1]

    # 1. If Worker wants to call a Tool -> Go to Tools
    if last_msg.tool_calls:
        return "tools"

    # 2. If Worker wrote a text response, verify it with Critic
    return "critic"


def should_loop(state: AgentState) -> Literal["llm_node", END]:
    time.sleep(5)
    messages = state['messages']
    last_msg = messages[-1] if messages else None

    # 1. If Critic passed (no new message added), End.
    if not last_msg or "SENIOR LEAD FEEDBACK" not in last_msg.content:
        return END

    # 2. Only check retries if we actually failed
    current_step = state.get("loop_step", 0)
    if current_step >= MAX_RETRIES:
        print("--- MAX RETRIES REACHED ---")
        return END

    # 3. Loop back to fix the mistake
    return "llm_node"


# --- 5. GRAPH CONSTRUCTION ---

workflow = StateGraph(AgentState)

# Add Nodes
workflow.add_node("llm_node", llm_node)
workflow.add_node("tools", ToolNode(tools))
workflow.add_node("critic", critic_node)

# Set Entry
workflow.set_entry_point("llm_node")

# Add Edges
# llm_node -> (Tools OR Critic)
workflow.add_conditional_edges(
    "llm_node",
    check_reflection,
    {"tools": "tools", "critic": "critic"}
)

# Tools -> Back to LLM (Standard ReAct loop)
workflow.add_edge("tools", "llm_node")

# Critic -> (Loop Back OR End)
workflow.add_conditional_edges(
    "critic",
    should_loop,
    {"llm_node": "llm_node", END: END}
)

checkpointer = MemorySaver()
app = workflow.compile(checkpointer=checkpointer)

print(f"--- Red Team Reflection Agent ({MODEL_NAME}) ---")

config = {
    "configurable": {"thread_id": "session_reflect_1"},
    "recursion_limit": 100  # Default is 25. Increased to 100 to support MAX_RETRIES=10
}
try:
    while True:
        u_in = input("\n[User]: ")
        if u_in.lower() in ["quit", "exit"]: break

        # Reset loop step on new user input
        initial_state = {"messages": [HumanMessage(content=u_in)], "loop_step": 0}

        for event in app.stream(initial_state, config=config):
            for key, value in event.items():
                if value and "messages" in value:
                    if len(value["messages"]) > 0:
                        messages = value["messages"]
                        if not isinstance(messages, list):
                            messages = [messages]

                        for msg in messages:
                            if isinstance(msg, BaseMessage) and msg.content:
                                if "SENIOR LEAD" in msg.content:
                                    print(f"\n\033[91m{msg.content}\033[0m")
                                elif isinstance(msg, ToolMessage):
                                    # Truncate Tool Output in console to reduce noise
                                    #truncated_content = (msg.content[:200] + '... [output truncated]') if len(msg.content) > 200 else msg.content
                                    print(f"\n[Tool Output]: {msg.content}")
                                else:
                                    print(f"\nAgent: {msg.content}")

                            if hasattr(msg, "tool_calls") and msg.tool_calls:
                                for t in msg.tool_calls:
                                    print(f"   (Calling Tool: {t['name']} args: {t['args']}...)")
except KeyboardInterrupt:
    print("program ended unexpectedly")
finally:
    msf_session.cleanup()