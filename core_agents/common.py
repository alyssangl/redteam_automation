"""
Shared utilities for the orchestrator and future stages.

Existing stages (recon.py, initial_access.py) keep their own copies.
New stages should import from here to avoid duplication.
"""

import json
import os
import re

import dotenv
import paramiko
from langchain_openai import ChatOpenAI
from langchain_core.messages import BaseMessage, SystemMessage
from langchain_core.tools import tool
from typing import List

dotenv.load_dotenv()

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

# Lab endpoints/creds are env-overridable (docker-compose / .env) with the
# original lab values as defaults — the framework is portable without code edits.
# See REPRODUCIBILITY.md and .env.example.
MODEL_NAME = os.getenv("LGG_MODEL", "gpt-4o-mini")
KALI_IP = os.getenv("KALI_IP", "192.168.34.6")      # attacker: Kali / msfrpcd host
TARGET_IP = os.getenv("TARGET_IP", "192.168.34.7")  # default target (graphs may override)
KALI_USER = os.getenv("KALI_USER", "kali")
KALI_PASS = os.getenv("KALI_PASS", "kali")
MSF_PORT = int(os.getenv("MSF_PORT", "55553"))
MSF_USER = os.getenv("MSF_USER", "kali")
MSF_PASS = os.getenv("MSF_PASS", "kali")

MAX_PIPELINE_RETRIES = 3

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
    model = ChatOpenAI(model=model_name, temperature=temperature, timeout=120)

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
# SHARED TOOLS
# =============================================================================

@tool
def tool_linux_terminal(command: str):
    """
    Executes a shell command on the remote Linux (Kali) terminal via SSH.

    **CRITICAL REQUIREMENT - NON-INTERACTIVE ONLY**:
    You MUST NOT use interactive or blocking commands (dangling commands).

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
