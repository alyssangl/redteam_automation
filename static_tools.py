# in static_nodes_and_types.py

# --- Imports for your tool ---
from langchain.tools import tool
import paramiko
import os


# --- STEP 1: DEFINE THE TOOL ---
@tool
def run_remote_pwd(hostname: str, username: str, pkey_path: str) -> str:
    """
    Connects to a remote machine via SSH using a private key and
    executes the 'pwd' (print working directory) command.

    Args:
        hostname (str): The server's IP address or hostname.
        username (str): The user to log in as.
        pkey_path (str): The local path to the private key file (e.g., /home/user/.ssh/id_rsa).
    """
    print(f"--- ATTEMPTING TOOL CALL: run_remote_pwd ---")
    print(f"--- Host: {hostname}, User: {username} ---")

    # Basic security check
    if not os.path.exists(pkey_path):
        return f"Error: Private key file not found at {pkey_path}"

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Load the private key
        private_key = paramiko.RSAKey.from_private_key_file(pkey_path)

        client.connect(hostname, username=username, pkey=private_key)

        stdin, stdout, stderr = client.exec_command("pwd")

        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()

        client.close()

        if error:
            return f"Error executing 'pwd': {error}"
        return f"Success! Output of 'pwd': {output}"

    except Exception as e:
        return f"SSH connection or command failed: {str(e)}"

# --- You would add other tools here ---
# @tool
# def list_remote_files(hostname: str, ...):
#     ...