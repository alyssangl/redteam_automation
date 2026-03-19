import os
import sys
import operator
import dotenv
from typing import TypedDict, Annotated, List

import paramiko
from langchain_openai import ChatOpenAI
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool

from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver
from tools.rag import query_knowledge_base


dotenv.load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

MODEL_NAME = "gpt-4.1"

KALI_IP = "192.168.34.6"
KALI_USER = "kali"
KALI_PASS = "kali"


def _run_ssh_command(command_str, description):
    """Helper to run SSH commands with streamed output"""
    print(f"\n[{description}] Connecting to Kali ({KALI_IP})...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=10)

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
            return f"Command '{command_str}' succeeded.\nOutput:\n{full_log}"
        else:
            return f"Command '{command_str}' failed (Exit Code: {exit_status}).\nError:\n{err_output}"

    except Exception as e:
        return f"SSH Connection/Execution Error: {str(e)}"
    finally:
        ssh.close()


@tool
def tool_linux_terminal(command: str):
    """
    Executes a command on the remote Linux (Kali) terminal via SSH.
    Use this to run tests, check IP configs, or verify RAG info.

    WARNING: non-interactive only.
    """
    forbidden = ["rm -rf /", ":(){ :|:& };:"]
    if any(bad in command for bad in forbidden):
        return "Command blocked by safety guardrails."

    print(f"\n[Terminal Tool] Executing: {command}")
    return _run_ssh_command(command, "Linux Terminal")


# --- AGENT SETUP ---

class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]


tools = [query_knowledge_base, tool_linux_terminal]


def llm_node(state: AgentState):
    messages = state['messages']

    sys_msg = SystemMessage(
        content=(
            f"You are a highly capable Red Team Assistant running on {MODEL_NAME}.\n"
            "Your goal is to assist the user with reconnaissance and penetration testing tasks.\n\n"
            "**OPERATIONAL LOGIC:**\n"
            "1. **Discovery Phase**: Use `tool_linux_terminal` to gather data (nmap, services, versions).\n"
            "2. **Intelligence Phase**: \n"
            "   - You MUST check `query_knowledge_base` for any service version you find.\n"
            "   - If the RAG tool returns a playbook/technique: **Follow it strictly.**\n"
            "   - If the RAG tool returns nothing: **You should try searching again, but is there really is still nothing after multiple attempts, you can inform the user, then use your own internal expert knowledge.**\n"
            "3. **Reporting Phase**: When using internal knowledge, briefly tag it as '(Standard Knowledge)' so the user distinguishes it from verified RAG docs.\n\n"
            "Be informative, and precise."
        )
    )

    model = ChatOpenAI(model=MODEL_NAME, temperature=0)
    model_with_tools = model.bind_tools(tools)

    response = model_with_tools.invoke([sys_msg] + messages)
    return {"messages": [response]}


workflow = StateGraph(AgentState)
workflow.add_node("llm_node", llm_node)
workflow.add_node("tools", ToolNode(tools))

workflow.set_entry_point("llm_node")
workflow.add_conditional_edges("llm_node", tools_condition)
workflow.add_edge("tools", "llm_node")

checkpointer = MemorySaver()
app = workflow.compile(checkpointer=checkpointer)

# --- EXECUTION ---
print("--- Recon Agent (Aggressive RAG) ---")

config = {"configurable": {"thread_id": "session_1"}}

while True:
    u_in = input("\n[User]: ")
    if u_in.lower() in ["quit", "exit"]: break

    initial_state = {"messages": [HumanMessage(content=u_in)]}

    for event in app.stream(initial_state, config=config):
        for key, value in event.items():
            if "messages" in value:
                last_msg = value["messages"][-1]

                # Print text response
                if hasattr(last_msg, "content") and last_msg.content:
                    print(f"Agent: {last_msg.content}")

                # Print tool usage specifically
                if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                    for t in last_msg.tool_calls:
                        print(f"   (Agent is calling tool: {t['name']} args: {t['args']}...)")