"""
Attack Graph — the core data structure for orchestrated penetration testing.

Design philosophy:
  - A NODE is a self-contained action. It has everything it needs to execute:
    the tool/module, parameters, target, objective. It produces findings.
  - An EDGE is a decision. It carries the REASONING for why we moved from
    one node to the next — what evidence was observed, what the agent concluded.
    e.g. "Recon found ProFTPD 1.3.5 on Linux → use proftpd_modcopy_exec"

The orchestrator walks the graph:
  1. Execute a node (self-contained — it knows what to do)
  2. Read its findings
  3. Decide which outgoing edge to traverse (based on evidence)
  4. The edge documents WHY that path was taken
  5. Move to the next node

Serializable to/from JSON for persistence, replay, and human review.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional


# =============================================================================
# ENUMS
# =============================================================================

class NodeStatus(str, Enum):
    """Lifecycle status of an attack node."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class EdgeCondition(str, Enum):
    """When an edge CAN be traversed (gate)."""
    ALWAYS = "always"
    ON_SUCCESS = "on_success"
    ON_FAILURE = "on_failure"
    CONDITIONAL = "conditional"


class Tactic(str, Enum):
    """MITRE ATT&CK tactics (Enterprise)."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


# =============================================================================
# COMMAND RECORD — individual command execution log
# =============================================================================

@dataclass
class CommandRecord:
    """A single command that was executed during a node's lifecycle."""
    command: str
    tool: str = ""              # "ssh", "msf_rpc", "session", "msf_console"
    output: str = ""
    exit_code: Optional[int] = None
    timestamp: str = ""
    duration_seconds: Optional[float] = None
    target: str = ""            # Where it ran: "kali", "target", "msf_console"
    success: bool = True
    note: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = _now()


# =============================================================================
# ATTACK NODE — a self-contained action
# =============================================================================

@dataclass
class AttackNode:
    """
    A self-contained attack action.

    The node knows everything it needs to execute: what module to run,
    what parameters to use, what the objective is. The orchestrator
    dispatches the node to a subagent, and the subagent writes back
    findings and commands.

    The node does NOT reference other nodes — that's the edge's job.
    """
    # --- Identity ---
    id: str                         # Unique ID: "recon_1", "exploit_proftpd", etc.
    label: str                      # Human-readable: "ProFTPD modcopy RCE"

    # --- Classification ---
    tactic: str = ""                # MITRE tactic: "initial_access", "persistence", etc.
    technique_id: str = ""          # MITRE technique: "T1210", "T1059.004"
    technique_name: str = ""        # "Exploitation of Remote Services"
    agent_type: str = ""            # Which subagent: "recon", "exploit", "privesc", etc.

    # --- What to do (self-contained) ---
    objective: str = ""             # Plain English: "Exploit ProFTPD 1.3.5 to get a shell"
    target_ip: str = ""
    tool_name: str = ""             # "nmap", "metasploit", "wipe", "ssh", etc.
    module: str = ""                # MSF module: "exploit/unix/ftp/proftpd_modcopy_exec"
    module_options: dict = field(default_factory=dict)
    # ^ {"RHOSTS": "10.0.0.5", "RPORT": 21, "LHOST": "192.168.34.6", ...}
    payload: str = ""               # MSF payload: "cmd/unix/reverse_python"
    payload_options: dict = field(default_factory=dict)
    # ^ {"LHOST": "192.168.34.6", "LPORT": 4444}
    commands_to_run: list[str] = field(default_factory=list)
    # ^ Pre-planned commands: ["apt install wipe -y", "wipe -f /tmp"]

    # --- Status ---
    status: str = NodeStatus.PENDING.value
    retries: int = 0
    max_retries: int = 3

    # --- Execution log (filled during/after execution) ---
    commands: list[CommandRecord] = field(default_factory=list)

    # --- Results (filled after execution) ---
    findings: dict = field(default_factory=dict)
    # ^ Free-form output. Schema depends on node type:
    #   Recon:    {ports: [...], os: "Linux", services: [...]}
    #   Exploit:  {session_id: "1", session_type: "meterpreter", access_level: "root"}
    #   PrivEsc:  {technique: "sudo", previous_level: "user", new_level: "root"}
    #   Impact:   {actions: [...], evidence: "..."}
    summary: str = ""               # One-line result: "Got meterpreter session 2 as root"

    # --- Timing ---
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""

    # --- Extensibility ---
    metadata: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.created_at:
            self.created_at = _now()

    # --- Lifecycle helpers ---

    @property
    def is_terminal(self) -> bool:
        return self.status in (NodeStatus.SUCCESS.value, NodeStatus.SKIPPED.value)

    @property
    def is_failed(self) -> bool:
        return self.status == NodeStatus.FAILED.value

    @property
    def can_retry(self) -> bool:
        return self.is_failed and self.retries < self.max_retries

    def mark_running(self):
        self.status = NodeStatus.RUNNING.value
        self.started_at = _now()

    def mark_success(self, findings: dict, summary: str = ""):
        self.status = NodeStatus.SUCCESS.value
        self.findings = findings
        self.summary = summary or str(findings)
        self.completed_at = _now()

    def mark_failed(self, reason: str = ""):
        self.retries += 1
        if self.retries >= self.max_retries:
            self.status = NodeStatus.FAILED.value
        else:
            self.status = NodeStatus.PENDING.value
        self.completed_at = _now()
        self.metadata["last_failure_reason"] = reason

    def mark_skipped(self, reason: str = ""):
        self.status = NodeStatus.SKIPPED.value
        self.completed_at = _now()
        self.metadata["skip_reason"] = reason

    def mark_blocked(self, reason: str = ""):
        self.status = NodeStatus.BLOCKED.value
        self.metadata["block_reason"] = reason

    def add_command(self, command: str, **kwargs) -> CommandRecord:
        record = CommandRecord(command=command, **kwargs)
        self.commands.append(record)
        return record


# =============================================================================
# EDGE CHECK — a single testable predicate on source findings
# =============================================================================

@dataclass
class EdgeCheck:
    """
    A single testable condition on the source node's findings.

    Each check looks at a specific field in findings and tests it.
    ALL checks on an edge must pass for the edge to be traversable.

    Supported operators:
        "exists"      — field is present and non-empty
        "not_exists"  — field is missing or empty
        "equals"      — field == expected
        "not_equals"  — field != expected
        "contains"    — expected is a substring of field value
        "in"          — field value is in the expected list
        "gt" / "gte"  — numeric greater than / greater or equal
        "lt" / "lte"  — numeric less than / less or equal
        "any_port"    — special: checks if any port in findings.ports matches

    Examples:
        EdgeCheck(field="ports", operator="any_port", expected={"port": 8181})
        EdgeCheck(field="os_detected", operator="contains", expected="Linux")
        EdgeCheck(field="access_level", operator="equals", expected="user")
        EdgeCheck(field="session_id", operator="exists")
    """
    field: str                      # Dot-path into source.findings: "ports", "os_detected", etc.
    operator: str = "exists"        # Test operator
    expected: Any = None            # Expected value (type depends on operator)
    description: str = ""           # Human-readable: "Port 8181 is open"

    def evaluate(self, findings: dict) -> bool:
        """Run this check against a findings dict. Returns True if check passes."""
        try:
            if self.operator == "any_port":
                return self._check_any_port(findings)

            value = _resolve_dotpath(findings, self.field) if self.field else findings
        except (KeyError, TypeError, IndexError):
            # Field doesn't exist in findings
            return self.operator == "not_exists"

        if self.operator == "exists":
            return value is not None and value != "" and value != []
        elif self.operator == "not_exists":
            return value is None or value == "" or value == []
        elif self.operator == "equals":
            return str(value) == str(self.expected)
        elif self.operator == "not_equals":
            return str(value) != str(self.expected)
        elif self.operator == "contains":
            return str(self.expected).lower() in str(value).lower()
        elif self.operator == "in":
            return str(value) in [str(v) for v in self.expected]
        elif self.operator == "gt":
            return float(value) > float(self.expected)
        elif self.operator == "gte":
            return float(value) >= float(self.expected)
        elif self.operator == "lt":
            return float(value) < float(self.expected)
        elif self.operator == "lte":
            return float(value) <= float(self.expected)
        else:
            return False  # Unknown operator

    def _check_any_port(self, findings: dict) -> bool:
        """
        Check if any port entry in findings['ports'] matches the expected criteria.

        expected can be:
            {"port": 8181}                          — port number only
            {"port": 22, "service": "ssh"}          — port + service
            {"service": "http"}                     — service only
            {"port": 21, "version": "ProFTPD 1.3.5"} — port + version substring
        """
        ports = findings.get("ports", [])
        if not isinstance(ports, list):
            return False

        expected = self.expected or {}
        for port_entry in ports:
            if not isinstance(port_entry, dict):
                continue
            match = True
            for key, val in expected.items():
                port_val = port_entry.get(key, "")
                if key in ("port", "rport"):
                    # Numeric comparison
                    match = match and (str(port_val) == str(val))
                else:
                    # Substring match for service/version
                    match = match and (str(val).lower() in str(port_val).lower())
            if match:
                return True
        return False

    def __str__(self) -> str:
        if self.description:
            return self.description
        if self.operator == "exists":
            return f"{self.field} exists"
        elif self.operator == "any_port":
            return f"port matching {self.expected} is open"
        else:
            return f"{self.field} {self.operator} {self.expected}"


# =============================================================================
# ATTACK EDGE — the decision / reasoning between nodes
# =============================================================================

@dataclass
class AttackEdge:
    """
    A directed edge from source → target that documents WHY this path was taken.

    The edge has three layers:
      1. GATE (condition) — basic status check: did the source succeed/fail?
      2. CHECKS — testable predicates on the source's findings data
         (e.g., "port 8181 is open", "OS contains Linux", "access_level == user")
      3. REASONING (evidence + rationale) — human-readable documentation of
         why this path was chosen, filled in during or after execution

    The edge is traversable when:
      - The gate condition is met (on_success, on_failure, always)
      - AND all checks pass against the source node's findings

    Examples:
      recon → rails_exploit:
          condition: on_success
          checks:
            - {field: "ports", operator: "any_port", expected: {"port": 8181},
               description: "Rails app on port 8181 is open"}
            - {field: "os_detected", operator: "contains", expected: "Linux",
               description: "Target is running Linux"}
          rationale: "Rails app with known secret_key_base on Linux"

      rails_exploit → persistence:
          condition: on_success
          checks:
            - {field: "session_id", operator: "exists",
               description: "Got an active session"}
            - {field: "session_type", operator: "equals", expected: "meterpreter",
               description: "Session is meterpreter (needed for post modules)"}
          rationale: "Meterpreter session required for service_persistence module"

      exploit_primary → exploit_fallback:
          condition: on_failure
          checks: []  (no checks needed — just needs failure)
          rationale: "Primary exploit failed, trying alternative vector"
    """
    source: str                     # Source node ID
    target: str                     # Target node ID

    # --- Gate: basic status check ---
    condition: str = EdgeCondition.ON_SUCCESS.value

    # --- Checks: testable predicates on source findings ---
    checks: list[EdgeCheck] = field(default_factory=list)

    # --- Reasoning: the WHY (documentation / audit trail) ---
    evidence: str = ""              # What was observed: "Found ProFTPD 1.3.5 on port 21"
    rationale: str = ""             # Why this path: "ProFTPD 1.3.5 has known RCE"

    # --- Extensibility ---
    label: str = ""
    metadata: dict = field(default_factory=dict)


# =============================================================================
# ATTACK GRAPH — the top-level container
# =============================================================================

@dataclass
class AttackGraph:
    """
    A directed graph representing an attack campaign.

    Nodes are self-contained actions. Edges are the decisions between them.
    The orchestrator walks the graph by executing nodes and following edges
    based on evidence.
    """
    # --- Identity ---
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""

    # --- Campaign context ---
    objective: str = ""
    target_ip: str = ""
    attacker_ip: str = ""
    scope: list[str] = field(default_factory=list)

    # --- Graph structure ---
    nodes: dict[str, AttackNode] = field(default_factory=dict)
    edges: list[AttackEdge] = field(default_factory=list)

    # --- Global accumulated intel ---
    known_credentials: list[dict] = field(default_factory=list)
    active_sessions: list[dict] = field(default_factory=list)
    discovered_hosts: list[dict] = field(default_factory=list)

    # --- Status ---
    status: str = "planned"
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""

    # --- Extensibility ---
    metadata: dict = field(default_factory=dict)
    version: str = "1.0"

    def __post_init__(self):
        if not self.created_at:
            self.created_at = _now()

    # -------------------------------------------------------------------------
    # Construction
    # -------------------------------------------------------------------------

    @classmethod
    def create(cls, objective: str, target_ip: str, **kwargs) -> AttackGraph:
        return cls(
            objective=objective,
            target_ip=target_ip,
            name=kwargs.pop("name", f"attack_{target_ip}"),
            **kwargs,
        )

    def add_node(self, node: AttackNode) -> AttackNode:
        if node.id in self.nodes:
            raise ValueError(f"Node '{node.id}' already exists")
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: AttackEdge) -> AttackEdge:
        if edge.source not in self.nodes:
            raise ValueError(f"Source node '{edge.source}' not found")
        if edge.target not in self.nodes:
            raise ValueError(f"Target node '{edge.target}' not found")
        self.edges.append(edge)
        return edge

    def connect(
        self,
        source_id: str,
        target_id: str,
        checks: list[EdgeCheck] = None,
        evidence: str = "",
        rationale: str = "",
        condition: str = EdgeCondition.ON_SUCCESS.value,
        **kwargs,
    ) -> AttackEdge:
        """Shorthand: create and add an edge with checks and reasoning."""
        edge = AttackEdge(
            source=source_id,
            target=target_id,
            checks=checks or [],
            evidence=evidence,
            rationale=rationale,
            condition=condition,
            **kwargs,
        )
        return self.add_edge(edge)

    def remove_node(self, node_id: str):
        self.nodes.pop(node_id, None)
        self.edges = [e for e in self.edges if e.source != node_id and e.target != node_id]

    def remove_edge(self, source: str, target: str):
        self.edges = [e for e in self.edges if not (e.source == source and e.target == target)]

    # -------------------------------------------------------------------------
    # Graph queries
    # -------------------------------------------------------------------------

    def get_node(self, node_id: str) -> AttackNode:
        return self.nodes[node_id]

    def predecessors(self, node_id: str) -> list[str]:
        return [e.source for e in self.edges if e.target == node_id]

    def successors(self, node_id: str) -> list[str]:
        return [e.target for e in self.edges if e.source == node_id]

    def incoming_edges(self, node_id: str) -> list[AttackEdge]:
        return [e for e in self.edges if e.target == node_id]

    def outgoing_edges(self, node_id: str) -> list[AttackEdge]:
        return [e for e in self.edges if e.source == node_id]

    def root_nodes(self) -> list[str]:
        targets = {e.target for e in self.edges}
        return [nid for nid in self.nodes if nid not in targets]

    def leaf_nodes(self) -> list[str]:
        sources = {e.source for e in self.edges}
        return [nid for nid in self.nodes if nid not in sources]

    def ready_nodes(self) -> list[str]:
        """Nodes that are PENDING and have all incoming edge conditions met."""
        ready = []
        for node_id, node in self.nodes.items():
            if node.status != NodeStatus.PENDING.value:
                continue
            incoming = self.incoming_edges(node_id)
            if not incoming:
                ready.append(node_id)
                continue
            if all(self._edge_satisfied(e) for e in incoming):
                ready.append(node_id)
        return ready

    def _edge_satisfied(self, edge: AttackEdge) -> bool:
        """
        Check if an edge is traversable. Two layers:
          1. GATE — source node status matches edge.condition
          2. CHECKS — all EdgeCheck predicates pass against source.findings
        """
        source = self.nodes.get(edge.source)
        if not source:
            return False

        # Layer 1: Gate — check source status
        gate_passed = False
        if edge.condition == EdgeCondition.ALWAYS.value:
            gate_passed = source.status in (NodeStatus.SUCCESS.value, NodeStatus.FAILED.value)
        elif edge.condition == EdgeCondition.ON_SUCCESS.value:
            gate_passed = source.status == NodeStatus.SUCCESS.value
        elif edge.condition == EdgeCondition.ON_FAILURE.value:
            gate_passed = source.status == NodeStatus.FAILED.value
        elif edge.condition == EdgeCondition.CONDITIONAL.value:
            # CONDITIONAL: gate passes if source is done (success or failed),
            # actual decision is in the checks
            gate_passed = source.status in (NodeStatus.SUCCESS.value, NodeStatus.FAILED.value)

        if not gate_passed:
            return False

        # Layer 2: Checks — evaluate each predicate against source findings
        if not edge.checks:
            return True  # No checks = gate is sufficient

        return all(check.evaluate(source.findings) for check in edge.checks)

    def is_complete(self) -> bool:
        return all(
            n.status in (NodeStatus.SUCCESS.value, NodeStatus.FAILED.value,
                         NodeStatus.SKIPPED.value, NodeStatus.BLOCKED.value)
            for n in self.nodes.values()
        )

    def success_rate(self) -> float:
        if not self.nodes:
            return 0.0
        succeeded = sum(1 for n in self.nodes.values() if n.status == NodeStatus.SUCCESS.value)
        return succeeded / len(self.nodes)

    # -------------------------------------------------------------------------
    # Context gathering — collect findings from predecessors for a node
    # -------------------------------------------------------------------------

    def gather_preceding_findings(self, node_id: str) -> dict:
        """
        Collect findings from all predecessor nodes, keyed by node ID.

        Returns:
            {"recon": {ports: [...], os: "Linux"}, "exploit_ssh": {session_id: "1", ...}}

        The orchestrator passes this to the subagent as context so it knows
        what upstream nodes discovered — but the node itself doesn't declare
        dependencies. The edge already documents why we arrived here.
        """
        result = {}
        for pred_id in self.predecessors(node_id):
            pred = self.nodes.get(pred_id)
            if pred and pred.findings:
                result[pred_id] = pred.findings
        return result

    # -------------------------------------------------------------------------
    # Serialization
    # -------------------------------------------------------------------------

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def from_dict(cls, data: dict) -> AttackGraph:
        graph = cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            objective=data.get("objective", ""),
            target_ip=data.get("target_ip", ""),
            attacker_ip=data.get("attacker_ip", ""),
            scope=data.get("scope", []),
            known_credentials=data.get("known_credentials", []),
            active_sessions=data.get("active_sessions", []),
            discovered_hosts=data.get("discovered_hosts", []),
            status=data.get("status", "planned"),
            created_at=data.get("created_at", ""),
            started_at=data.get("started_at", ""),
            completed_at=data.get("completed_at", ""),
            metadata=data.get("metadata", {}),
            version=data.get("version", "1.0"),
        )
        for node_data in data.get("nodes", {}).values():
            node = _node_from_dict(node_data)
            graph.nodes[node.id] = node
        for edge_data in data.get("edges", []):
            checks_data = edge_data.pop("checks", [])
            edge = AttackEdge(
                **edge_data,
                checks=[EdgeCheck(**c) for c in checks_data],
            )
            graph.edges.append(edge)
        return graph

    @classmethod
    def from_json(cls, text: str) -> AttackGraph:
        return cls.from_dict(json.loads(text))

    @classmethod
    def load(cls, path: str | Path) -> AttackGraph:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    # -------------------------------------------------------------------------
    # Display
    # -------------------------------------------------------------------------

    def summary(self) -> str:
        lines = [
            f"AttackGraph: {self.name} ({self.id})",
            f"  Objective: {self.objective}",
            f"  Target: {self.target_ip}",
            f"  Status: {self.status}",
            f"  Nodes: {len(self.nodes)}  Edges: {len(self.edges)}",
            f"  Success rate: {self.success_rate():.0%}",
            "",
            "  Nodes:",
        ]
        for node in self.nodes.values():
            icon = {
                "pending": "○", "running": "▶", "success": "✓",
                "failed": "✗", "skipped": "⊘", "blocked": "⊗",
            }.get(node.status, "?")
            module_str = f"  ({node.module})" if node.module else ""
            lines.append(f"    {icon} {node.id}: {node.label}{module_str} [{node.status}]")

        if self.edges:
            lines.append("")
            lines.append("  Edges:")
            for edge in self.edges:
                cond = f" [{edge.condition}]" if edge.condition != "on_success" else ""
                reason = f' — "{edge.rationale}"' if edge.rationale else ""
                lines.append(f"    {edge.source} → {edge.target}{cond}{reason}")
                for check in edge.checks:
                    lines.append(f"      ? {check}")

        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"AttackGraph(id={self.id!r}, nodes={len(self.nodes)}, edges={len(self.edges)})"


# =============================================================================
# HELPERS
# =============================================================================

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_dotpath(data: dict, path: str) -> Any:
    current = data
    for key in path.split("."):
        if isinstance(current, dict):
            current = current[key]
        elif isinstance(current, list) and key.isdigit():
            current = current[int(key)]
        else:
            raise KeyError(f"Cannot resolve '{key}' in {type(current)}")
    return current


def _node_from_dict(data: dict) -> AttackNode:
    commands_data = data.pop("commands", [])
    node = AttackNode(
        id=data["id"],
        label=data.get("label", ""),
        tactic=data.get("tactic", ""),
        technique_id=data.get("technique_id", ""),
        technique_name=data.get("technique_name", ""),
        agent_type=data.get("agent_type", ""),
        objective=data.get("objective", ""),
        target_ip=data.get("target_ip", ""),
        tool_name=data.get("tool_name", ""),
        module=data.get("module", ""),
        module_options=data.get("module_options", {}),
        payload=data.get("payload", ""),
        payload_options=data.get("payload_options", {}),
        commands_to_run=data.get("commands_to_run", []),
        status=data.get("status", NodeStatus.PENDING.value),
        retries=data.get("retries", 0),
        max_retries=data.get("max_retries", 3),
        commands=[CommandRecord(**c) for c in commands_data],
        findings=data.get("findings", {}),
        summary=data.get("summary", ""),
        created_at=data.get("created_at", ""),
        started_at=data.get("started_at", ""),
        completed_at=data.get("completed_at", ""),
        metadata=data.get("metadata", {}),
        tags=data.get("tags", []),
    )
    return node
