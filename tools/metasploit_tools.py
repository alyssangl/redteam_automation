from pymetasploit3.msfrpc import MsfRpcClient
from langchain_core.tools import tool
import os
import re
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

        # Container lab: LHOST is the VirtualBox host-only adapter IP (192.168.34.1),
        # which the Kali *container* does not hold -- a reverse handler that binds LHOST
        # literally fails with "Handler failed to bind" (EADDRNOTAVAIL). Bind ALL reverse
        # handlers to 0.0.0.0 globally; the target still dials back to LHOST and Docker
        # forwards the published ports (4444-4480) into the container. (proftpd's graph set
        # this per-module; doing it globally here covers every path -- direct execution,
        # the exploit subagent, and replanner-grown exploits -- through this one console.)
        try:
            self.send_command("setg ReverseListenerBindAddress 0.0.0.0", timeout=10)
        except Exception:
            pass

    def send_command(self, command, timeout=60):
        """Sends a command and waits for the prompt to return."""
        # Clean the command
        command = command.strip()

        # F1: a failed exploit attempt leaves its reverse-handler JOB bound to the
        # LPORT; the next attempt (even the CORRECT exploit) then fails to bind that
        # port ("binding issues on listener port" / "address already in use"), which
        # blocks recovery on retry-heavy graphs (flaw_initial_access: the subagent
        # picked proftpd_modcopy correctly but couldn't bind). Before firing an
        # exploit, clear stale handler jobs so the fresh handler can bind. Sessions
        # are unaffected (jobs != sessions); guarded to exploit-fire verbs so it is
        # not re-entrant (the jobs -K below is not itself a run/exploit).
        low = command.lower()
        if low == "run" or low.startswith("run ") or low == "exploit" or low.startswith("exploit "):
            try:
                self.console.write("jobs -K\n")
                time.sleep(1)
                for _ in range(3):   # drain jobs -K output so it doesn't bleed into the exploit's
                    r = self.console.read()
                    if not r.get('busy') and not r.get('data'):
                        break
                    time.sleep(0.3)
            except Exception:
                pass

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
        # A bare `sleep N` on the single-threaded reverse_perl command_shell freezes
        # it (no job control), so every SUBSEQUENT read returns "(no output)" — the
        # bug that blocked cron heartbeat verification. Waits belong off the target
        # shell: intercept a standalone sleep and wait on the orchestrator instead,
        # keeping the session responsive. (Compound commands that merely contain
        # 'sleep' are left alone — only a lone `sleep N` is the footgun.)
        _sleep = re.fullmatch(r"sleep\s+(\d+)", command.strip())
        if _sleep:
            n = min(int(_sleep.group(1)), 75)
            time.sleep(n)
            return f"(waited {n}s on the orchestrator; the target session was NOT blocked)"
        session_type = self.get_session_type(session_id)
        if session_type is None:
            return f"Error: Session {session_id} not found. Use tool_list_sessions() to list active sessions."

        # Decode bytes if needed
        if isinstance(session_type, bytes):
            session_type = session_type.decode('utf-8', errors='ignore')

        sid = str(session_id)

        if 'meterpreter' in session_type:
            # meterpreter_write targets the meterpreter COMMAND INTERPRETER, which only
            # understands meterpreter verbs (getuid, sysinfo, upload, ...). A POSIX shell
            # command like `crontab`/`echo`/`useradd` comes back as "Unknown command" —
            # so persistence (all shell work) silently no-ops on an upgraded session.
            # Fix: drop into a channelized system shell (`shell`) and run the command
            # THERE, framing the output with the same end-marker trick as the raw
            # command_shell path below. Self-contained per call — drain -> shell ->
            # cmd + marker -> read-to-marker -> exit — so the session is left back at the
            # meterpreter prompt for the next call.
            done = "__MSF_CMD_DONE_9271__"
            poke = 'echo __MSF""_CMD_DONE_9271__\n'
            self.client.call('session.meterpreter_read', [sid])          # clear leftover
            self.client.call('session.meterpreter_write', [sid, 'shell\n'])
            time.sleep(2)
            self.client.call('session.meterpreter_read', [sid])          # drain shell banner
            self.client.call('session.meterpreter_write', [sid, command + "\n"])
            self.client.call('session.meterpreter_write', [sid, poke])
            output = ""
            elapsed = 0
            while elapsed < timeout:
                resp = self.client.call('session.meterpreter_read', [sid])
                data = resp.get(b'data', resp.get('data', b''))
                if isinstance(data, bytes):
                    data = data.decode('utf-8', errors='ignore')
                output += data
                if done in output:
                    output = output.split(done)[0]   # keep only the real output
                    break
                time.sleep(1)
                elapsed += 1
            # Leave the shell channel so the session returns to the meterpreter prompt.
            try:
                self.client.call('session.meterpreter_write', [sid, 'exit\n'])
                time.sleep(1)
                self.client.call('session.meterpreter_read', [sid])
            except Exception:
                pass
            output = output.strip()
            return output if output else "(no output)"
        else:
            # command_shell — output streams back asynchronously AND some payloads
            # (notably UnrealIRCd's reverse_perl) don't flush a command's output until
            # the NEXT write pokes the shell, so a bounded wait still misses it and the
            # output leaks into the following command's read (F5b). Robust fix: write the
            # command, THEN write a unique end-marker echo. The marker write flushes the
            # command's buffered output, and the marker's echoed value is a definitive
            # "output complete" signal — read until it appears (or timeout), then return
            # everything before it. The marker is split with "" in the echo COMMAND so
            # that, even if a shell echoes stdin, the literal token appears only in the
            # echo's OUTPUT, never in the command text.
            done = "__MSF_CMD_DONE_9271__"
            poke = 'echo __MSF""_CMD_DONE_9271__\n'
            self.client.call('session.shell_write', [sid, command + "\n"])
            self.client.call('session.shell_write', [sid, poke])
            output = ""
            elapsed = 0
            idle = 0
            repokes = 0
            while elapsed < timeout:
                resp = self.client.call('session.shell_read', [sid])
                data = resp.get(b'data', resp.get('data', b''))
                if isinstance(data, bytes):
                    data = data.decode('utf-8', errors='ignore')
                output += data
                if done in output:
                    output = output.split(done)[0]   # keep only the real output
                    break
                # A flaky reverse_perl command_shell can swallow the marker echo (it
                # flushes buffered output only on the NEXT write). On a read stall,
                # (a) tell a DEAD session apart from a merely-slow one via the RPC
                # session list — NEVER the wedge-prone interactive console — and
                # (b) re-poke the shell to force the flush. Without this, a live but
                # slow session returns "(no output)", the caller assumes the session
                # died and falls back to tool_metasploit_rpc('sessions') (which wedges
                # into 'sessions -i' mode and spews "received: 0"), and cron heartbeat
                # verification never grounds even though /tmp/.hb did get written.
                if data:
                    idle = 0
                else:
                    idle += 1
                    if idle >= 3:
                        idle = 0
                        if self.get_session_type(sid) is None:
                            return (f"Error: Session {session_id} not found. "
                                    f"Use tool_list_sessions() to see active sessions.")
                        if repokes < 3:
                            repokes += 1
                            self.client.call('session.shell_write', [sid, poke])
                time.sleep(1)
                elapsed += 1
            output = output.strip()
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


@tool
def tool_list_sessions():
    """List active Metasploit sessions via the RPC session API.

    Use this to check whether a session is still alive (e.g. after a command
    returns no output). It queries the RPC session list directly and NEVER touches
    the interactive msfconsole, so — unlike tool_metasploit_rpc("sessions") — it
    cannot wedge into "sessions -i" mode and return "Wrong number of arguments...
    received: 0". Returns each active session's id, type and info, or a clear
    "No active sessions." when none exist.
    """
    try:
        result = msf_session.client.call('session.list') or {}
    except Exception as e:
        return f"Error listing sessions: {e.__class__.__name__}: {e}"
    if not result:
        return "No active sessions."
    lines = []
    for sid, details in result.items():
        sid_s = sid.decode() if isinstance(sid, bytes) else str(sid)
        def _dec(v):
            return v.decode('utf-8', errors='ignore') if isinstance(v, bytes) else str(v)
        stype = _dec(details.get(b'type', details.get('type', b'')))
        info = _dec(details.get(b'info', details.get('info', b'')))
        lines.append(f"Session {sid_s}: {stype} {info}".strip())
    return "\n".join(lines)