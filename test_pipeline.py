"""
Live integration test for the full killchain pipeline.

Runs the orchestrator end-to-end against the lab environment and prints
a structured test report.

Usage:
    python test_pipeline.py
    python test_pipeline.py --target 192.168.34.7 --objective "Get a shell and read /etc/shadow"
    python test_pipeline.py -t 192.168.34.7 -o "Exploit Samba and prove root" -f my_results.json
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

import paramiko

from core_agents.common import KALI_IP, KALI_USER, KALI_PASS

# Stage display names, keyed by findings dict key prefix
STAGE_DISPLAY = {
    "recon": "Recon",
    "initial_access": "InitAccess",
    "persistence": "Persistence",
    "privesc": "PrivEsc",
    "impact": "Impact",
}

FINDINGS_KEYS = {
    "recon": "recon_findings",
    "initial_access": "exploitation_findings",
    "persistence": "persistence_findings",
    "privesc": "privesc_findings",
    "impact": "impact_findings",
}


# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

def check_ssh() -> bool:
    """Verify Kali SSH is reachable."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=5)
        ssh.close()
        return True
    except Exception as e:
        print(f"  [FAIL] SSH to {KALI_IP}: {e}")
        return False


def check_openai_key() -> bool:
    """Verify OPENAI_API_KEY is set."""
    if os.getenv("OPENAI_API_KEY"):
        return True
    print("  [FAIL] OPENAI_API_KEY not set in environment")
    return False


def check_msf_rpc() -> bool:
    """Verify Metasploit RPC is importable (connects at import time)."""
    try:
        import tools.metasploit_tools  # noqa: F401
        return True
    except Exception as e:
        print(f"  [FAIL] Metasploit RPC: {e}")
        return False


def run_preflight() -> bool:
    """Run all pre-flight checks. Returns True if all pass."""
    print("Pre-flight checks:")
    checks = [
        ("SSH to Kali", check_ssh),
        ("OpenAI API key", check_openai_key),
        ("Metasploit RPC", check_msf_rpc),
    ]

    all_ok = True
    for name, fn in checks:
        ok = fn()
        status = "OK" if ok else "FAIL"
        print(f"  [{status}] {name}")
        if not ok:
            all_ok = False

    return all_ok


# =============================================================================
# STAGE SUMMARY HELPERS
# =============================================================================

def summarize_recon(findings: dict) -> str:
    """One-line summary from recon findings."""
    if not findings:
        return "no data"
    ports = findings.get("open_ports", [])
    if ports:
        port_str = ", ".join(str(p) for p in ports[:6])
        return f"{len(ports)} open ports ({port_str})"
    return findings.get("summary", "ran")[:80]


def summarize_exploitation(findings: dict) -> str:
    """One-line summary from exploitation findings."""
    if not findings:
        return "no data"
    if findings.get("success"):
        sid = findings.get("session_id", "?")
        stype = findings.get("session_type", "?")
        exploit = findings.get("exploit_used", "?")
        return f"{stype} session {sid} via {exploit}"
    return findings.get("summary", "no session")[:80]


def summarize_persistence(findings: dict) -> str:
    """One-line summary from persistence findings."""
    if not findings:
        return "no data"
    method = findings.get("method", "")
    if findings.get("success") and method:
        return f"{method} installed"
    return findings.get("summary", "skipped")[:80]


def summarize_privesc(findings: dict) -> str:
    """One-line summary from privesc findings."""
    if not findings:
        return "no data"
    technique = findings.get("technique", "")
    new_level = findings.get("new_level", "")
    if findings.get("success") and technique:
        return f"{technique} -> {new_level}"
    if new_level == "root" or "already" in findings.get("summary", "").lower():
        return "already_root (skipped)"
    return findings.get("summary", "skipped")[:80]


def summarize_impact(findings: dict) -> str:
    """One-line summary from impact findings."""
    if not findings:
        return "no data"
    actions = findings.get("actions", [])
    if findings.get("success"):
        return f"{len(actions)} actions taken, objective achieved"
    return findings.get("summary", "skipped")[:80]


STAGE_SUMMARIZERS = {
    "recon": summarize_recon,
    "initial_access": summarize_exploitation,
    "persistence": summarize_persistence,
    "privesc": summarize_privesc,
    "impact": summarize_impact,
}


# =============================================================================
# REPORT
# =============================================================================

def format_duration(seconds: float) -> str:
    """Format seconds into Xm Ys."""
    m, s = divmod(int(seconds), 60)
    if m > 0:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def print_report(results: dict, duration: float, output_path: str):
    """Print the structured test report to stdout."""
    target = results.get("target_ip", "?")
    objective = results.get("objective", "?")
    verdict = results.get("critic_verdict", "UNKNOWN")
    attempts = results.get("attempts", 0)

    sep = "=" * 64
    thin = "-" * 64

    print(f"\n{sep}")
    print("  PIPELINE TEST REPORT")
    print(sep)
    print(f"  Target:           {target}")
    print(f"  Objective:        {objective}")
    print(f"  Duration:         {format_duration(duration)}")
    print(f"  Overall Verdict:  {verdict}")
    print(thin)
    print("  STAGE RESULTS:")

    for stage in ["recon", "initial_access", "persistence", "privesc", "impact"]:
        findings_key = FINDINGS_KEYS[stage]
        findings = results.get(findings_key, {})
        success = findings.get("success", False)
        mark = "+" if success else "x"
        label = STAGE_DISPLAY[stage].ljust(12)
        summary = STAGE_SUMMARIZERS[stage](findings)
        print(f"  [{mark}] {label} -- {summary}")

    print(thin)
    print(f"  Critic verdict:      {verdict}")
    print(f"  Pipeline attempts:   {attempts}")
    print(f"  Results saved to:    {output_path}")
    print(f"{sep}\n")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Run the full killchain pipeline against the lab and report results.",
    )
    parser.add_argument(
        "-t", "--target",
        default="192.168.34.7",
        help="Target IP address (default: 192.168.34.7)",
    )
    parser.add_argument(
        "-o", "--objective",
        default="Gain root access on the target",
        help='Attack objective string (default: "Gain root access on the target")',
    )
    parser.add_argument(
        "-f", "--output",
        default=None,
        help="Path to save JSON results (default: test_results_<timestamp>.json)",
    )
    args = parser.parse_args()

    # Resolve output path
    if args.output is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"test_results_{ts}.json"
    else:
        output_path = args.output

    # --- Pre-flight ---
    if not run_preflight():
        print("\nPre-flight checks failed. Fix the issues above and retry.")
        sys.exit(1)

    print(f"\nStarting pipeline: target={args.target}  objective=\"{args.objective}\"\n")

    # --- Run pipeline ---
    from core_agents.orchestrator import run_pipeline

    start = time.time()
    try:
        results = run_pipeline(target_ip=args.target, objective=args.objective)
    except KeyboardInterrupt:
        print("\nPipeline interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nPipeline crashed: {e}")
        sys.exit(1)
    duration = time.time() - start

    # --- Save JSON results ---
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    # --- Report ---
    print_report(results, duration, output_path)

    # --- Exit code ---
    verdict = results.get("critic_verdict", "")
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
