#!/usr/bin/env bash
# Start sshd (for tool_linux_terminal) then msfrpcd in the FOREGROUND so the
# container stays alive and a fresh RPC daemon is guaranteed per `up` (this is
# also the lab-hygiene fix — a fresh msfrpcd avoids the stale-handler wedge).
set -e

: "${MSF_USER:=kali}"
: "${MSF_PASS:=kali}"
: "${MSF_PORT:=55553}"

echo "[kali] starting sshd..."
service ssh start || /usr/sbin/sshd

# Initialise the MSF database (optional; silences warnings, enables some post mods)
echo "[kali] initialising msf database (best-effort)..."
msfdb init >/dev/null 2>&1 || true

echo "[kali] starting msfrpcd on 0.0.0.0:${MSF_PORT} as user '${MSF_USER}' (foreground)"
exec msfrpcd -U "${MSF_USER}" -P "${MSF_PASS}" -p "${MSF_PORT}" -a 0.0.0.0 -f
