import os
from typing import Annotated, TypedDict
from langchain_openai import ChatOpenAI
from langchain_community.tools.tavily_search import TavilySearchResults
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.messages import BaseMessage
from operator import add

class State(TypedDict):
    messages: Annotated[list[BaseMessage], add]

# 2. 設定工具與模型
tools = [TavilySearchResults(max_results=2)]
tool_node = ToolNode(tools)

# 這裡我已經幫你處理好 bind_tools 了
model = ChatOpenAI(model="gpt-5-nano").bind_tools(tools)

# 3. 定義節點函數
def call_model(state: State):
    response = model.invoke(state["messages"])
    return {"messages": [response]}

# 4. 構建圖 (這裡有 Bug!)
workflow = StateGraph(State)

workflow.add_node("agent", call_model)
workflow.add_node("action", tool_node)

# 設定進入點
workflow.set_entry_point("agent")

# --- 關鍵 Debug 區域 ---
# 我定義了一個條件連線，但這裡少了一個「邏輯判斷函數」
# 導致 Agent 執行完一次後就會直接卡住或報錯
workflow.add_edge("action", "agent")
workflow.add_edge("agent", END)
# ----------------------

# 5. 編譯
app = workflow.compile(checkpointer=MemorySaver())

# 6. 執行
config = {"configurable": {"thread_id": "debug_101"}}
input_message = {"messages": [("user", "現在台北幾度？")]}

for event in app.stream(input_message, config):
    for v in event.values():
        print(v)