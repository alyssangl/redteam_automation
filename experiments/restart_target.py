"""
restart_target.py — snapshot-restore + reboot the Metasploitable 3 target VM.

The UnrealIRCd backdoor degrades under heavy use (HANDOFF §4.2 #4): after dozens of
re-exploits the spawned shells read-zombie / sessions stop opening, which confounded
an entire overnight batch. Restoring the target to a clean snapshot BEFORE each run
gives every cell a fresh target, eliminating that confounder.

Restores the VM to a snapshot (default: the newest, `network up`), boots it headless,
and waits until the target answers on the UnrealIRCd port (6667) FROM KALI — the only
reachability that matters, since the orchestrator drives everything through Kali.

Usage:
    python experiments/restart_target.py                 # restore 'network up' + wait
    python experiments/restart_target.py --snapshot clean
    python experiments/restart_target.py --no-wait       # restore+boot, don't block
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

VBOXMANAGE = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
VM_NAME = "Metasploitable3-ub1404"
DEFAULT_SNAPSHOT = "network up"
TARGET_IP = "192.168.34.7"
TARGET_PORT = 6667


def _vbox(*args, timeout=120) -> subprocess.CompletedProcess:
    return subprocess.run([VBOXMANAGE, *args], capture_output=True, text=True,
                          timeout=timeout)


def _is_running() -> bool:
    r = _vbox("list", "runningvms", timeout=30)
    return VM_NAME in (r.stdout or "")


def _target_up_from_kali(timeout: int = 8) -> bool:
    """True iff the target answers on UnrealIRCd:6667 as seen FROM KALI (nmap over
    SSH) — the reachability the orchestrator actually depends on."""
    try:
        import stages.recon as recon
        out = recon.run_ssh_command(
            f"nmap -Pn -p{TARGET_PORT} --host-timeout 20s {TARGET_IP} 2>/dev/null "
            f"| grep -E '{TARGET_PORT}/tcp'",
            timeout=timeout + 25,
        )
        return f"{TARGET_PORT}/tcp open" in (out or "")
    except Exception:
        return False


def restore_and_boot(snapshot: str = DEFAULT_SNAPSHOT, wait: bool = True,
                     boot_timeout: int = 240) -> bool:
    """Power off (if running), restore the snapshot, boot headless, optionally wait
    until 6667 is reachable from Kali. Returns True if the target is up (or wait
    was skipped), False on timeout."""
    if _is_running():
        print(f"[target] powering off {VM_NAME}...", flush=True)
        _vbox("controlvm", VM_NAME, "poweroff", timeout=60)
        time.sleep(5)

    print(f"[target] restoring snapshot '{snapshot}'...", flush=True)
    r = _vbox("snapshot", VM_NAME, "restore", snapshot, timeout=120)
    if r.returncode != 0:
        print(f"[target] restore FAILED: {r.stderr.strip()[:200]}", file=sys.stderr)
        return False

    print(f"[target] booting {VM_NAME} headless...", flush=True)
    r = _vbox("startvm", VM_NAME, "--type", "headless", timeout=120)
    if r.returncode != 0:
        print(f"[target] startvm FAILED: {r.stderr.strip()[:200]}", file=sys.stderr)
        return False

    if not wait:
        print("[target] booted (not waiting for services).", flush=True)
        return True

    print(f"[target] waiting for {TARGET_IP}:{TARGET_PORT} (UnrealIRCd) from Kali "
          f"(up to {boot_timeout}s)...", flush=True)
    deadline = time.time() + boot_timeout
    while time.time() < deadline:
        if _target_up_from_kali():
            waited = int(boot_timeout - (deadline - time.time()))
            print(f"[target] UP — 6667 reachable after ~{waited}s.", flush=True)
            return True
        time.sleep(10)
    print(f"[target] TIMEOUT — {TARGET_PORT} not reachable within {boot_timeout}s.",
          file=sys.stderr)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Snapshot-restore + reboot the target VM.")
    ap.add_argument("--snapshot", default=DEFAULT_SNAPSHOT)
    ap.add_argument("--no-wait", action="store_true", help="don't block on reachability")
    ap.add_argument("--boot-timeout", type=int, default=240)
    args = ap.parse_args()
    ok = restore_and_boot(args.snapshot, wait=not args.no_wait,
                          boot_timeout=args.boot_timeout)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
