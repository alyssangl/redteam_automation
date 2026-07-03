from pymetasploit3.msfrpc import MsfRpcClient
from langchain_core.tools import tool
import os
import time

class MetasploitSession:
    def __init__(self, host, port, user, password):
        print(f"--- Connecting to Metasploit RPC ({host}:{port}) ---")
        # SSL is True by default for msfrpcd unless you specifically disabled it
        self.client = MsfRpcClient(password, username=user, server=host, port=port, ssl=True)

        # Create a persistent console
        self.console = self.client.consoles.console()
        self.cid = self.console.cid
        print(f"--- Console Created (ID: {self.cid}) ---")

    def send_command(self, command, timeout=60):
        """Sends a command and waits for the prompt to return."""
        # Clean the command
        command = command.strip()

        # Write to the persistent console
        self.console.write(command + "\n")

        output = ""
        start_time = time.time()

        while time.time() - start_time < timeout:
            response = self.console.read()
            chunk = response.get('data', '')
            output += chunk

            # STOPPING CONDITION:
            # We stop if we see the standard prompt (msf6 >) OR
            # if we see a shell prompt (C:\>, #, $) if we are inside a session.
            # We also check if 'busy' is False, but MSF is tricky with that.
            if not response.get('busy') and len(output) > 0:
                # Slight delay to ensure buffer is flushed
                time.sleep(0.5)
                # One last read to catch tail end
                output += self.console.read().get('data', '')
                break

            time.sleep(1)

        return output

    def get_session_type(self, session_id):
        """Query session.list and return the session type string (e.g., 'shell' or 'meterpreter')."""
        result = self.client.call('session.list')
        # Keys can be int or str depending on msgpack decoding
        for sid, details in result.items():
            if str(sid) == str(session_id):
                return details.get(b'type', details.get('type', b'shell'))
        return None

    def run_session_command(self, session_id, command, timeout=10):
        """Execute a command directly on a session using the session API.

        Auto-detects session type (command_shell vs meterpreter) and uses
        the correct RPC method. Returns output string.

        Bypasses the MSF console entirely — each command is atomic and targeted.
        """
        session_type = self.get_session_type(session_id)
        if session_type is None:
            return f"Error: Session {session_id} not found. Use tool_metasploit_rpc('sessions') to list active sessions."

        # Decode bytes if needed
        if isinstance(session_type, bytes):
            session_type = session_type.decode('utf-8', errors='ignore')

        sid = str(session_id)

        if 'meterpreter' in session_type:
            self.client.call('session.meterpreter_write', [sid, command])
            time.sleep(2)
            output = ""
            elapsed = 0
            while elapsed < timeout:
                resp = self.client.call('session.meterpreter_read', [sid])
                data = resp.get(b'data', resp.get('data', b''))
                if isinstance(data, bytes):
                    data = data.decode('utf-8', errors='ignore')
                output += data
                if data:
                    break
                time.sleep(1)
                elapsed += 1
            return output if output else "(no output)"
        else:
            # command_shell — append newline to execute
            self.client.call('session.shell_write', [sid, command + "\n"])
            time.sleep(2)
            output = ""
            elapsed = 0
            while elapsed < timeout:
                resp = self.client.call('session.shell_read', [sid])
                data = resp.get(b'data', resp.get('data', b''))
                if isinstance(data, bytes):
                    data = data.decode('utf-8', errors='ignore')
                output += data
                if not data:
                    break
                time.sleep(1)
                elapsed += 1
            return output if output else "(no output)"

    def cleanup(self):
        """Destroy the console to free memory on Kali."""
        try:
            self.client.consoles.destroy(self.cid)
            print(f"--- Console {self.cid} Destroyed ---")
        except:
            pass


# --- GLOBAL SESSION INSTANCE (LAZY) ---
# Previously this connected to msfrpcd at import time, which coupled importing
# ANY stage/orchestrator module to a live lab and made offline unit-testing
# impossible. _LazyMsfSession defers the real connection until the first
# attribute access, so `import stages.*` / `import core_agents.orchestrator`
# succeed with no lab, and the RPC connection is made on first actual use.
class _LazyMsfSession:
    # Read from the environment so the lab moves without code edits (matches
    # core_agents/common.py). In the container lab KALI_IP is the compose DNS
    # name `kali`; the old 192.168.34.6 (Kali-VM LAN IP) is the fallback default.
    _CFG = dict(
        host=os.getenv("KALI_IP", "192.168.34.6"),
        port=int(os.getenv("MSF_PORT", "55553")),
        user=os.getenv("MSF_USER", "kali"),
        password=os.getenv("MSF_PASS", "kali"),
    )

    def __init__(self):
        self._real = None

    def _ensure(self):
        if self._real is None:
            self._real = MetasploitSession(**self._CFG)
        return self._real

    def __getattr__(self, name):
        # __getattr__ runs only for attrs not found normally (i.e. everything
        # except _real/_ensure/_CFG) -> delegate to the real session, connecting
        # on first use.
        return getattr(self._ensure(), name)


msf_session = _LazyMsfSession()


@tool
def tool_session_command(session_id: str, command: str):
    """Execute a command ON THE TARGET through an active Metasploit session.

    This runs directly on the compromised target machine — NOT on Kali.
    Uses the MSF session API (session.shell_write/read) for reliable, atomic command execution.

    Use for: whoami, id, crontab -l, cat /etc/passwd, mkdir, echo, chmod, etc.

    Args:
        session_id: The MSF session ID (e.g., "3")
        command: The command to run on the target
    """
    return msf_session.run_session_command(session_id, command)