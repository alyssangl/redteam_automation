"""
Shared data contracts for the orchestrator pipeline.

Defines:
- Stage findings TypedDicts (output contracts for each killchain stage)
- PipelineState (the LangGraph state that flows through the orchestrator)
- STAGES constant listing the stage execution order
"""

import operator
from typing import TypedDict, Annotated, List

from langchain_core.messages import BaseMessage

# =============================================================================
# STAGE FINDINGS — output contracts
# =============================================================================

# Re-export existing stage findings (no duplication)
from stages.recon import ReconFindings
from stages.initial_access import ExploitationFindings


class PersistenceFindings(TypedDict):
    """Output contract for the persistence stage (not yet implemented)."""
    success: bool
    method: str       # e.g. "cron_job", "ssh_key", "service"
    details: str      # What was persisted and how
    summary: str


class PrivEscFindings(TypedDict):
    """Output contract for the privilege escalation stage (not yet implemented)."""
    success: bool
    technique: str        # e.g. "sudo_miscfg", "kernel_exploit", "suid"
    previous_level: str   # "user" | "root"
    new_level: str        # "root"
    summary: str


class ImpactFindings(TypedDict):
    """Output contract for the impact stage (not yet implemented)."""
    success: bool
    actions: list     # List of impact actions taken
    summary: str


# =============================================================================
# ORCHESTRATOR PIPELINE STATE
# =============================================================================

class PipelineState(TypedDict):
    """Top-level LangGraph state for the orchestrator pipeline.

    Each stage writes to its own findings key — flat top-level keys avoid
    merge conflicts in LangGraph state channels.
    """
    messages: Annotated[List[BaseMessage], operator.add]
    objective: str              # User's attack objective
    target_ip: str              # Primary target IP
    plan: str                   # Planner's attack plan text
    current_stage: str          # "recon" | "initial_access" | "persistence" | "privesc" | "impact"
    recon_findings: dict        # ReconFindings as dict
    exploitation_findings: dict # ExploitationFindings as dict
    persistence_findings: dict  # PersistenceFindings as dict
    privesc_findings: dict      # PrivEscFindings as dict
    impact_findings: dict       # ImpactFindings as dict
    loop_step: int
    critic_verdict: str         # "PASS" | "FAIL"
    critic_feedback: str        # Specific failure feedback for planner


# =============================================================================
# CONSTANTS
# =============================================================================

STAGES = ["recon", "initial_access", "persistence", "privesc", "impact"]
