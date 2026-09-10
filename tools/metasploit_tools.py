from pymetasploit3.msfrpc import MsfRpcClient
from langchain_core.tools import tool
import os
import re
import threading
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

    # Sentinel appended to send_command output when a console op wedged. It rides
    # back through the orchestrator's output-preview log line into the run log, so
    # parse_eval can mark the whole cell CONFOUNDED (a wedged msfrpcd is a lab
    # artifact to discard/retry, NOT a real exploit failure) instead of counting
    # it as a genuine v0 failure.
    WEDGE_SENTINEL = "[MSF_CONSOLE_WEDGED]"

    # Per-op wall-clock caps (seconds) for the SESSION RPC api (shell_read/
    # meterpreter_read/session.list) used by run_session_command. The msgpack RPC
    # socket has NO timeout, so a wedged msfrpcd makes session.*_read block
    # FOREVER — and because the read loop counts `elapsed` only on healthy reads,
    # a single wedged read froze the whole stage (elapsed never advanced). These
    # caps run every session RPC on a daemon thread with a hard ceiling (same
    # pattern send_command uses for the console) so a wedge is detected and
    # abandoned instead of hanging.
    _RPC_READ_CAP = 15
    _RPC_WRITE_CAP = 15

    def _bounded_call(self, fn, timeout, label):
        """Run a synchronous msfrpc console op (write/read) on a DAEMON thread with
        a hard wall-clock cap. The msgpack RPC socket has no timeout, so when
        msfrpcd/the socket wedges the op blocks FOREVER — this is what froze whole
        benchmark runs mid-`use exploit/...` (the hang was `console.write`, not the
        read loop). A daemon thread means a leaked (still-blocked) op can never keep
        the interpreter alive at exit. Returns (result, ok); ok=False on
        wedge/error."""
        box: dict = {}
        done = threading.Event()

        def _worker():
            try:
                box["r"] = fn()
            except Exception as e:  # noqa: BLE001 — surface, don't propagate to a dead thread
                box["e"] = e
            finally:
                done.set()

        threading.Thread(target=_worker, daemon=True).start()
        if not done.wait(timeout=max(1, timeout)):
            print(f"[msf] console {label} wedged (> {timeout:.0f}s) -- abandoning "
                  f"(msfrpcd likely wedged)")
            return None, False
        if "e" in box:
            print(f"[msf] console {label} error: {box['e']}")
            return None, False
        return box.get("r"), True

    def _bounded_read(self, per_read_timeout):
        """self.console.read() bounded by a real wall-clock cap. Returns the read
        dict, or None if the read wedged/errored."""
        r, ok = self._bounded_call(self.console.read, per_read_timeout, "read")
        return r if ok else None

    def _bounded_client_call(self, method, args, timeout, label):
        """Run a raw msgpack RPC (self.client.call) on a daemon thread with a hard
        wall-clock cap. The RPC socket has no timeout, so a wedged msfrpcd blocks
        the call forever; inside run_session_command's read loop that means
        `elapsed` never advances and the whole stage hangs. Returns (result, ok);
        ok=False on wedge/error (mirrors _bounded_call, used by send_command).

        `args is None` preserves the exact `client.call(method)` (no-args) form."""
        if args is None:
            fn = lambda: self.client.call(method)          # noqa: E731
        else:
            fn = lambda: self.client.call(method, args)    # noqa: E731
        return self._bounded_call(fn, timeout, label)

    def _sess_read(self, method, sid, timeout):
        """One bounded session read (session.shell_read / session.meterpreter_read).
        Returns the decoded output string ("" when the read was empty), or None
        when the read wedged/errored past the cap — the caller BREAKS on None so a
        wedged msfrpcd can never spin the loop forever."""
        resp, ok = self._bounded_client_call(method, [sid], timeout, method)
        if not ok or resp is None:
            return None
        data = resp.get(b'data', resp.get('data', b''))
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='ignore')
        return data

    def _sess_write(self, method, sid, payload):
        """One bounded session write (session.shell_write / session.meterpreter_write).
        Best-effort: a wedged write is abandoned after the cap and the following
        bounded read is what terminates the loop. Returns True on a clean write."""
        _, ok = self._bounded_client_call(method, [sid, payload], self._RPC_WRITE_CAP, method)
        return ok

    def send_command(self, command, timeout=60):
        """Sends a command and waits for the prompt to return.

        The read loop is bounded by a real wall-clock `timeout` (see
        _bounded_read) so a wedged console can never hang the caller."""
        # Clean the command
        command = command.strip()

        start_time = time.time()

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
                self._bounded_call(lambda: self.console.write("jobs -K\n"), 15, "write")
                time.sleep(1)
                for _ in range(3):   # drain jobs -K output so it doesn't bleed into the exploit's
                    r = self._bounded_read(per_read_timeout=10)
                    if r is None or (not r.get('busy') and not r.get('data')):
                        break
                    time.sleep(0.3)
            except Exception:
                pass

        # Write to the persistent console. This is the OTHER unbounded RPC call
        # (the read loop below is already bounded): a wedged msfrpcd froze whole
        # runs here mid-`use exploit/...`. Bound it too, and if it wedges, surface
        # the sentinel so the cell is scored CONFOUNDED rather than a real failure.
        _, wrote = self._bounded_call(
            lambda: self.console.write(command + "\n"), 15, "write")
        if not wrote:
            return self.WEDGE_SENTINEL

        output = ""
        while time.time() - start_time < timeout:
            remaining = timeout - (time.time() - start_time)
            response = self._bounded_read(per_read_timeout=remaining)
            if response is None:
                # Read wedged past the wall-clock cap — stop. If we never got any
                # output, flag it as a wedge so the cell is scored CONFOUNDED.
                if not output:
                    output = self.WEDGE_SENTINEL
                break
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
                tail = self._bounded_read(per_read_timeout=5)
                if tail is not None:
                    output += tail.get('data', '')
                break

            time.sleep(1)

        return output

    def get_session_type(self, session_id):
        """Query session.list and return the session type string (e.g., 'shell' or 'meterpreter').

        Bounded (session.list is a blocking RPC with no socket timeout, and this
        is called INSIDE run_session_command's read loop — a wedge here would hang
        the loop). Returns None if the list call wedged/errored."""
        result, ok = self._bounded_client_call('session.list', None, self._RPC_READ_CAP, "session.list")
        if not ok or not result:
            return None
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
        # Per-read wall-clock cap: never exceed the caller's nominal `timeout`, but
        # floor at 2s so a wedged read is still detectable. Every session RPC below
        # goes through _sess_read/_sess_write (bounded) so a wedged msfrpcd can
        # never block this call forever.
        read_cap = max(2, min(timeout, self._RPC_READ_CAP))

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
            self._sess_read('session.meterpreter_read', sid, read_cap)          # clear leftover
            self._sess_write('session.meterpreter_write', sid, 'shell\n')
            time.sleep(2)
            self._sess_read('session.meterpreter_read', sid, read_cap)          # drain shell banner
            self._sess_write('session.meterpreter_write', sid, command + "\n")
            self._sess_write('session.meterpreter_write', sid, poke)
            output = ""
            elapsed = 0
            while elapsed < timeout:
                data = self._sess_read('session.meterpreter_read', sid, read_cap)
                if data is None:
                    break   # wedged msfrpcd read — stop rather than block/spin forever
                output += data
                if done in output:
                    output = output.split(done)[0]   # keep only the real output
                    break
                time.sleep(1)
                elapsed += 1
            # Leave the shell channel so the session returns to the meterpreter prompt.
            try:
                self._sess_write('session.meterpreter_write', sid, 'exit\n')
                time.sleep(1)
                self._sess_read('session.meterpreter_read', sid, read_cap)
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
            self._sess_write('session.shell_write', sid, command + "\n")
            self._sess_write('session.shell_write', sid, poke)
            output = ""
            elapsed = 0
            idle = 0
            repokes = 0
            while elapsed < timeout:
                data = self._sess_read('session.shell_read', sid, read_cap)
                if data is None:
                    break   # wedged msfrpcd read — stop rather than block/spin forever
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
                            self._sess_write('session.shell_write', sid, poke)
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

    # First MSF use lazily connects: MsfRpcClient(...) + consoles.console() are
    # synchronous RPC calls with NO timeout, so a slow/wedged msfrpcd hangs the
    # whole run at first use (observed: a cell froze 40 min at the first
    # `use exploit/...`). Bound the connect on a daemon thread so it fails fast
    # instead of burning the per-cell cap. Override via MSF_CONNECT_TIMEOUT.
    _CONNECT_TIMEOUT = int(os.getenv("MSF_CONNECT_TIMEOUT", "60"))

    def __init__(self):
        self._real = None
        # Tracks the most recent connect worker's completion. Used to avoid
        # STACKING connect threads: if a prior attempt timed out and its worker is
        # STILL running (msfrpcd wedged), we must not spawn another leaking thread.
        self._pending = None

    def _ensure(self):
        if self._real is not None:
            return self._real

        # Don't stack connect threads. If a previous _ensure timed out and its
        # worker never returned (msfrpcd truly wedged), _pending stays un-set —
        # spawning more workers would leak an unbounded number of threads (and
        # each may eventually create an orphan console). Fail fast until the
        # outstanding attempt resolves. A resolved worker (success OR abandoned-
        # cleanup) sets its event, which re-enables a fresh attempt.
        if self._pending is not None and not self._pending.is_set():
            raise RuntimeError(
                "MSF connect already in flight and unresolved (msfrpcd wedged) "
                "— failing fast instead of stacking connect threads")

        box: dict = {}
        done = threading.Event()
        # abandoned/lock close the race between "waiter gives up" and "worker
        # finishes": exactly one of them takes ownership of the freshly-created
        # session, and whoever does NOT own it destroys its console so a late
        # connect can never strand an orphaned console on msfrpcd (msfrpcd wedge).
        abandoned = threading.Event()
        lock = threading.Lock()
        self._pending = done

        def _connect():
            try:
                s = MetasploitSession(**self._CFG)
            except Exception as e:  # noqa: BLE001
                with lock:
                    box["e"] = e
                    done.set()
                return
            leak = False
            with lock:
                if abandoned.is_set():
                    leak = True          # waiter already gave up — we must clean up
                else:
                    box["s"] = s
                done.set()
            if leak:
                # Destroy the console this late connect created; leaving it would
                # wedge msfrpcd (the discarded box is never cleaned up otherwise).
                try:
                    s.cleanup()
                except Exception:
                    pass

        threading.Thread(target=_connect, daemon=True).start()
        if not done.wait(timeout=self._CONNECT_TIMEOUT):
            with lock:
                abandoned.set()
                # The worker may have beaten us to the lock and stored a session;
                # take ownership and destroy its console so it doesn't leak.
                stranded = box.pop("s", None)
            if stranded is not None:
                try:
                    stranded.cleanup()
                except Exception:
                    pass
            raise RuntimeError(
                f"MSF connect/console-create exceeded {self._CONNECT_TIMEOUT}s "
                f"(msfrpcd wedged/slow) — failing fast instead of hanging")
        if "e" in box:
            raise box["e"]
        self._real = box["s"]
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