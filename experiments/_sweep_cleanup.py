"""Throwaway sweep helper: kill all MSF sessions + handler jobs on the shared
msfrpcd so the next sweep run starts with clean state (frees reverse-handler
ports, drops stale sessions). Runs inside the app container. Safe to delete."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.metasploit_tools import msf_session as m

try:
    print(m.send_command("sessions -K", timeout=20))
    print(m.send_command("jobs -K", timeout=20))
finally:
    try:
        m.cleanup()
    except Exception:
        pass
