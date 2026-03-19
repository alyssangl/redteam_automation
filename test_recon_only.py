"""
Run the pipeline and stop after the recon stage.
Reports what the Universal Planner and Recon Agent did.
"""

import json
import sys
import time
import uuid

from dotenv import load_dotenv
load_dotenv()

from langchain_core.messages import HumanMessage, AIMessage
from langgraph.checkpoint.memory import MemorySaver

from core_agents.orchestrator import build_pipeline
from core_agents.common import Colors, print_colored, MAX_PIPELINE_RETRIES

TARGET_IP = "192.168.34.7"
OBJECTIVE = "Gain root access on the target"


def main():
    # --- Preflight ---
    from test_pipeline import run_preflight
    if not run_preflight():
        print("\nPre-flight checks failed.")
        sys.exit(1)

    thread_id = f"recon_test_{uuid.uuid4().hex[:8]}"

    workflow = build_pipeline()
    checkpointer = MemorySaver()

    # Compile WITH interrupt_after recon_stage — pipeline pauses after recon
    app = workflow.compile(
        checkpointer=checkpointer,
        interrupt_after=["recon_stage"],
    )

    config = {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": 200,
    }

    initial_state = {
        "messages": [HumanMessage(content=f"Attack objective: {OBJECTIVE}\nTarget: {TARGET_IP}")],
        "objective": OBJECTIVE,
        "target_ip": TARGET_IP,
        "plan": "",
        "current_stage": "",
        "recon_findings": {},
        "exploitation_findings": {},
        "persistence_findings": {},
        "privesc_findings": {},
        "impact_findings": {},
        "loop_step": 0,
        "critic_verdict": "",
        "critic_feedback": "",
    }

    sep = "=" * 70
    print(f"\n{sep}")
    print(f"  RECON-ONLY TEST RUN")
    print(f"  Target: {TARGET_IP}")
    print(f"  Objective: {OBJECTIVE}")
    print(f"  Thread: {thread_id}")
    print(f"{sep}\n")

    start = time.time()

    # Stream — will stop after recon_stage due to interrupt_after
    for event in app.stream(initial_state, config=config):
        for key, value in event.items():
            print(f"\n--- Node completed: {key} ---")
            if not value or "messages" not in value:
                continue
            messages = value["messages"]
            if not isinstance(messages, list):
                messages = [messages]
            for msg in messages:
                if not hasattr(msg, "content") or not msg.content:
                    continue
                print(f"  {msg.content[:600]}")
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    for t in msg.tool_calls:
                        print(f"   -> Tool call: {t['name']} args: {str(t['args'])[:200]}")

    duration = time.time() - start

    # Extract final state at interrupt point
    snapshot = app.get_state(config)
    state = snapshot.values

    print(f"\n{sep}")
    print(f"  POST-RECON REPORT  (stopped after recon, {duration:.0f}s elapsed)")
    print(f"{sep}")

    # --- Universal Planner report ---
    plan = state.get("plan", "")
    print(f"\n[1] UNIVERSAL PLANNER")
    print(f"    Plan length: {len(plan)} chars")
    if plan:
        print(f"    Plan text:\n")
        for line in plan.split("\n"):
            print(f"      {line}")
    else:
        print("    (no plan captured)")

    # --- Recon Agent report ---
    recon = state.get("recon_findings", {})
    print(f"\n[2] RECON AGENT")
    print(f"    Success: {recon.get('success', 'N/A')}")
    print(f"    Target IP: {recon.get('target_ip', 'N/A')}")
    print(f"    OS detected: {recon.get('os_detected', 'N/A')}")
    print(f"    Hostname: {recon.get('hostname', 'N/A')}")
    print(f"    Summary: {recon.get('summary', 'N/A')}")

    ports = recon.get("ports", [])
    if ports:
        print(f"    Open ports ({len(ports)}):")
        for p in ports:
            print(f"      {p.get('port', '?')}/tcp  {p.get('service', '?')}  {p.get('version', '')}")
    else:
        print("    Open ports: none found")

    # Recon sub-agents detail
    print(f"\n    --- Recon Sub-Agents ---")
    print(f"    [2a] Recon Planner: Designed nmap scan strategy (RAG-assisted)")
    print(f"    [2b] Recon Executor: Executed nmap commands via SSH to Kali")
    print(f"    [2c] Recon Critic: Evaluated scan quality, verdict = {'PASS' if recon.get('success') else 'FAIL'}")

    raw_nmap = recon.get("raw_nmap_output", "")
    if raw_nmap:
        # Show last 2000 chars of raw nmap
        display = raw_nmap[-2000:] if len(raw_nmap) > 2000 else raw_nmap
        print(f"\n    Raw nmap output (last {len(display)} chars):")
        for line in display.split("\n"):
            print(f"      {line}")

    print(f"\n{sep}")
    print(f"  Pipeline stopped after recon. Duration: {duration:.0f}s")
    print(f"{sep}\n")

    # Dump full recon findings as JSON
    print("Full recon_findings JSON:")
    print(json.dumps(recon, indent=2, default=str))


if __name__ == "__main__":
    main()