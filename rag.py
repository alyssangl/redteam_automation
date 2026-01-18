import os
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from langchain.tools import tool
import dotenv

# 1. CONFIGURATION (Must match the builder script)
DB_PATH = "./my_knowledge_base"
OPENAI_MODEL = "text-embedding-3-small"

# Get Key
dotenv.load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# 2. Initialize DB Connection
# We initialize this once so we don't reconnect every time the tool is called
if OPENAI_API_KEY:
    embeddings = OpenAIEmbeddings(model=OPENAI_MODEL, api_key=OPENAI_API_KEY)
    vector_db = Chroma(
        persist_directory=DB_PATH,
        embedding_function=embeddings,
        collection_name="my_rag_collection"
    )
else:
    vector_db = None
    print("WARNING: OPENAI_API_KEY not set in rag_tool.py. Tool will fail if called.")


@tool
def query_knowledge_base(query: str) -> str:
    """
    Use this tool to look up information from the internal knowledge base.
    Useful for answering questions about uploaded documents, policies, or specific data.
    """
    if not vector_db:
        return "Error: Database not initialized due to missing API Key."

    # Create retriever (k=3 means top 3 results)
    retriever = vector_db.as_retriever(search_kwargs={"k": 3})

    # Fetch relevant chunks
    docs = retriever.invoke(query)

    # Format for the LLM
    results = []
    for doc in docs:
        results.append(f"rag_tools_called:\nContent: {doc.page_content}\nSource: {doc.metadata.get('source', 'unknown')}")

    return "\n\n".join(results)