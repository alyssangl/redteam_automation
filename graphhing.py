import sys

from static_nodes_and_types import *
from langgraph.graph import StateGraph, END

workflow_builder = StateGraph(MyWorkflowState)

# Add nodes to the "canvas"
workflow_builder.add_node("llm_call", call_llm)
workflow_builder.add_node("formatter", node_b)

# Set the "Start" node
workflow_builder.set_entry_point("llm_call")

# Draw the "wires"
workflow_builder.add_edge("llm_call", "formatter")
workflow_builder.add_edge("formatter", END)

# --- STEP 4: COMPILE AND RUN ---
app = workflow_builder.compile()

print("--- Enter your question (or 'exit' to quit) ---")
for line in sys.stdin:
    user_question = line.strip()

    if user_question.lower() == 'exit':
        print("Goodbye!")
        break

    # This is the key change:
    # We use the user's question to create the 'inputs' dictionary
    inputs = {"message": user_question}

    print("--- Running Workflow ---")
    final_result = app.invoke(inputs)
    print("--- Output ---")
    print(final_result['message'])
    print("--- Enter your question (or 'exit' to quit) ---")