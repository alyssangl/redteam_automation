from typing import TypedDict
from langchain_openai import ChatOpenAI
import os

os.environ["OPENAI_API_KEY"] = "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"
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