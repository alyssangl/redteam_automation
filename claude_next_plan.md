# Next Steps Plan

## 1. Build the Hybrid Replanner (PRIORITY)

The orchestrator currently walks the graph strictly — if an edge check fails, downstream nodes get blocked and the run ends. We need a replanner that can **grow new edges** when the predefined path is blocked.

### How it should work:
```
Orchestrator runs node → success
  → check outgoing edges
  → all edge checks FAIL (no viable path forward)
  → REPLANNER activates:
    1. Reads current graph state (what succeeded, what's blocked, findings so far)
    2. LLM analyzes: "I have a session from ssh_bruteforce but no path to disk_wipe"
    3. LLM proposes: "Add edge ssh_bruteforce → disk_wipe" or "Add new node + edges"
    4. Graph is modified (new edges/nodes added)
    5. Orchestrator continues walking the updated graph
```

### Key design decisions:
- Replanner only activates when `explore=True` (or a new flag like `replan=True`)
- In strict mode (`explore=False`), blocked = blocked. No replanning.
- The replanner should be a single LLM call, not a full agent loop
- It receives: graph summary, completed node findings, blocked nodes, objective
- It outputs: new edges (and optionally new nodes) to add to the graph

### Where this was needed:
- SSH brute force succeeded (session 1 opened as vagrant)
- But `rails_exploit` edge check failed (port 8181 not found)
- Everything downstream (persistence → reconnect → disk_wipe) stayed pending
- Replanner would see "I have a session, disk_wipe needs a session, connect them"

---

## 2. Fix the Disk Wipe Graph for Metasploitable 3 (AFTER replanner)

The CREME disk wipe scenario targets a different VM (with Rails on 8181). Metasploitable 3 has:
```
21/ftp    ProFTPD 1.3.5      (vulnerable to modcopy CVE-2015-3306)
22/ssh    OpenSSH 6.6.1p1    (brute force works — vagrant:vagrant)
80/http   Apache 2.4.7
445/smb   Samba 4.3.11       (vulnerable to is_known_pipename CVE-2017-7494)
6667/irc  UnrealIRCd         (nmap shows it but exploit may not work on this build)
```

### Simpler graph that works:
```
recon → ssh_bruteforce → privesc (sudo) → disk_wipe
```
- vagrant has `(ALL : ALL) NOPASSWD: ALL` — instant root via sudo
- No persistence/reconnect needed — direct path
- `sudo apt-get install -y wipe && sudo wipe -f /tmp`

### Node details:
- **recon**: nmap full scan (same as now)
- **ssh_bruteforce**: `auxiliary/scanner/ssh/ssh_login` with USER_FILE + PASS_FILE (working!)
- **privesc**: `sudo id && sudo whoami` via session commands (verify root)
- **disk_wipe**: `sudo apt-get install -y wipe && sudo wipe -f /tmp` via session commands

---

## 3. Current State Summary

### What works:
- AttackGraph datatype with nodes, edges, EdgeChecks ✓
- Orchestrator graph walker with `ready_nodes()` loop ✓
- Direct execution in strict mode (zero LLM calls for MSF modules) ✓
- SSH brute force succeeded: vagrant:vagrant, session 1 opened ✓
- Edge checks correctly block paths (port 8181 FAIL) ✓
- Logging with per-graph log files ✓
- Checkpoint only on success ✓

### What's blocked/missing:
- **Replanner** — IMPLEMENTED as backtracking walker + `_replan_from()`. Untested (Kali was down).
- **Explore fallback** — token bloat is fixed (trimmed raw_recon) but untested
- **Disk wipe graph** — CREME scenario doesn't match Metasploitable 3 (needs simpler graph, see section 2)
- **Session command nodes** — `_execute_session_commands` written but untested
- **Test the backtracking walker** — need Kali + target up to run end-to-end
