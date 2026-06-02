"""Lab hygiene: restart msfrpcd on Kali to a CLEAN state (clears stale handler
jobs / dead sessions that cause "Exploit completed, but no session was created").

Why setsid: launching the daemon over a paramiko `exec_command` with `nohup ... &`
did NOT reliably survive the channel closing — msfrpcd kept dropping. `setsid`
fully detaches it from the SSH session/process group, so it stays up.

Usage:
    python experiments/restart_msf.py
"""
from __future__ import annotations
import time, warnings
warnings.filterwarnings("ignore")
import paramiko

KALI = "192.168.34.6"
USER = PASS = "kali"
PORT = 55553


def _login() -> bool:
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        MsfRpcClient(PASS, username=USER, server=KALI, port=PORT, ssl=True)
        return True
    except Exception:
        return False


def restart() -> bool:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(KALI, port=22, username=USER, password=PASS, timeout=10)
    c.exec_command("pkill -f msfrpcd", timeout=15)
    time.sleep(3)
    # setsid => survives the SSH channel closing (nohup did not, reliably)
    c.exec_command(
        f"bash -lc 'setsid msfrpcd -P {PASS} -U {USER} >/tmp/msfrpcd.log 2>&1 </dev/null'",
        timeout=15,
    )
    c.close()
    for i in range(18):
        if _login():
            print(f"msfrpcd up after ~{i*5}s")
            # stability: confirm it stays up
            stable = all((_login() or time.sleep(7)) for _ in range(3))
            print("STABLE" if stable else "FLAPPING")
            return stable
        time.sleep(5)
    print("FAILED to come up in 90s")
    return False


if __name__ == "__main__":
    import sys
    sys.exit(0 if restart() else 1)
