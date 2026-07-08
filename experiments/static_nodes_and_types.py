from typing import TypedDict
from langchain_openai import ChatOpenAI
import os

# OPENAI_API_KEY comes from the environment (.env / compose), never hardcoded.
# The revoked key that used to live here was leaked in git history — rotate it.
assert os.getenv("OPENAI_API_KEY"), "Set OPENAI_API_KEY in your environment/.env"
llm = ChatOpenAI(model="gpt-5-mini-2025-08-07")

class MyWorkflowState(TypedDict):
    message: str


def call_llm(state: MyWorkflowState):
    """
    Node 1: Calls the LLM.
    It takes the 'message' from the state, sends it to the LLM,
    and returns the LLM's response.
    """
    print("--- Executing Node 1 (call_llm) ---")

    # Get the user's question from the state
    question = state['message']

    # Call the LLM
    response = llm.invoke(question)

    # Return a dictionary to update the 'message' field in the state
    # This *overwrites* the user's question with the LLM's answer.
    return {"message": response.content}


def node_b(state: MyWorkflowState):
    """
    This is our "Second" node. It reads from the state and updates it.
    """
    print("--- Executing Node B ---")
    # Get the current message from the state
    current_message = state['message']

    # Append to it
    new_message = "ChatGPT says: " + current_message

    # Return the update
    return {"message": new_message}