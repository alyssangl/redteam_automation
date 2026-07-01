#!/usr/bin/env bash
# On container start: bring up sshd, then run a FRESH msfrpcd and KEEP it alive.
#
# A fresh msfrpcd on every start is also the lab-hygiene fix — it clears stale
# jobs/sessions/handlers (the wedge that shows up as 120s-per-command in the
# logs). The supervise loop restarts msfrpcd in-container if it ever exits;
# docker-compose's `restart: unless-stopped` covers the container/daemon itself
# dropping (e.g. Docker Desktop being killed).
set -u

: "${MSF_USER:=kali}"
: "${MSF_PASS:=kali}"
: "${MSF_PORT:=55553}"

echo "[kali] starting sshd..."
service ssh start || /usr/sbin/sshd

echo "[kali] initialising msf database (best-effort)..."
msfdb init >/dev/null 2>&1 || true

# Supervise msfrpcd: kill any stale instance, start fresh, restart on exit.
while true; do
  pkill -f msfrpcd 2>/dev/null || true
  echo "[kali] starting fresh msfrpcd on 0.0.0.0:${MSF_PORT} as user '${MSF_USER}'"
  msfrpcd -U "${MSF_USER}" -P "${MSF_PASS}" -p "${MSF_PORT}" -a 0.0.0.0 -f
  echo "[kali] msfrpcd exited (code $?) — restarting fresh in 3s..."
  sleep 3
done
