import os
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from langchain.tools import tool
from langchain_core.documents import Document
import dotenv

# 1. CONFIGURATION (Must match the builder script)
DB_PATH = "../databases/my_knowledge_base"
OPENAI_MODEL = "text-embedding-3-small"

# Get Key
dotenv.load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# 2. Initialize DB Connection
# We initialize this once so we don't reconnect every time the tool is called
_db_cache = {}

def _get_db(db_path: str) -> Chroma:
    """Return a cached Chroma instance for the given path."""
    if db_path not in _db_cache:
        if not OPENAI_API_KEY:
            return None
        os.makedirs(db_path, exist_ok=True)
        embeddings = OpenAIEmbeddings(model=OPENAI_MODEL, api_key=OPENAI_API_KEY)
        _db_cache[db_path] = Chroma(
            persist_directory=db_path,
            embedding_function=embeddings,
            collection_name="my_rag_collection"
        )
    return _db_cache[db_path]

# Pre-load default DB
if OPENAI_API_KEY:
    vector_db = _get_db(DB_PATH)
else:
    vector_db = None
    print("WARNING: OPENAI_API_KEY not set in rag_tool.py. Tool will fail if called.")


@tool
def query_knowledge_base(query: str, db_name: str = "") -> str:
    """
    Use this tool to look up information from the internal knowledge base.
    Useful for answering questions about uploaded documents, policies, or specific data.
    - query: The search query
    - db_name: Optional database name under ./databases/ (default: my_knowledge_base).
    - **Query Expansion Rule**: NEVER search for just a software name (e.g., 'Samba').
    - **Construct a Verbose Query**: Include the target software, the version, AND the desired goal.
    - BAD: query_knowledge_base('Samba 4.3.11')
    - GOOD: query_knowledge_base('Remote code execution exploit for Samba 4.3.11 using shared library loading or symlink vulnerabilities')
    """
    # Ablation V5 (-RAG): return no intelligence so the subagent must proceed on
    # the model's parametric knowledge alone. Kept here so every caller is covered.
    try:
        from core_agents.eval_flags import rag_enabled
        if not rag_enabled():
            return "No results found in the knowledge base for this query."
    except Exception:
        pass

    if db_name:
        db = _get_db(os.path.join("../databases", db_name))
    else:
        db = vector_db

    if not db:
        return "Error: Database not initialized due to missing API Key."

    # Create retriever (k=3 means top 3 results)
    retriever = db.as_retriever(search_kwargs={"k": 3})

    # Fetch relevant chunks
    docs = retriever.invoke(query)

    # Format for the LLM
    results = []
    for doc in docs:
        results.append(f"rag_tools_called:\nContent: {doc.page_content}\nSource: {doc.metadata.get('source', 'unknown')}")

    return "\n\n".join(results)


@tool
def add_to_knowledge_base(content: str, source: str = "agent_runtime") -> str:
    """
    Add a text document to the knowledge base at runtime.
    Use this to store useful findings, exploit notes, or recon data for future retrieval.
    - content: The text to store
    - source: A label describing where this came from (e.g., 'nmap_scan', 'exploit_notes')
    """
    if not vector_db:
        return "Error: Database not initialized."
    doc = Document(
        page_content=content,
        metadata={"source": source, "type": "runtime_addition"}
    )
    vector_db.add_documents([doc])
    return f"Added document to knowledge base (source: {source}, {len(content)} chars)."


@tool
def query_successful_attacks(query: str) -> str:
    """
    Search the database of PROVEN past successful attacks.
    Call this FIRST before query_knowledge_base — past successes are the highest-value intelligence.
    - query: Verbose search query (e.g., "ProFTPD 1.3.5 remote code execution")
    """
    # Ablation V5 (-RAG): the proven-attacks DB is part of the RAG layer too.
    try:
        from core_agents.eval_flags import rag_enabled
        if not rag_enabled():
            return "No past successful attacks found for this query. Proceed to query the main knowledge base."
    except Exception:
        pass

    db_path = os.path.join("../databases", "successful_attacks")
    try:
        db = _get_db(db_path)
    except Exception:
        return "No successful attacks database available yet. Proceed to query the main knowledge base."
    if not db:
        return "No successful attacks database available yet. Proceed to query the main knowledge base."

    retriever = db.as_retriever(search_kwargs={"k": 3})
    docs = retriever.invoke(query)
    if not docs:
        return "No past successful attacks found for this query. Proceed to query the main knowledge base."

    results = []
    for doc in docs:
        results.append(f"past_attack_found:\nContent: {doc.page_content}\nSource: {doc.metadata.get('source', 'unknown')}")
    return "\n\n".join(results)


def log_successful_attack(content: str, metadata: dict = None) -> str:
    """Programmatically log a successful attack to the dedicated success DB."""
    db_path = os.path.join("../databases", "successful_attacks")
    db = _get_db(db_path)
    if not db:
        return "Error: Database not initialized (missing API key)."
    meta = {"source": "attack_log", "type": "successful_attack"}
    if metadata:
        meta.update(metadata)
    doc = Document(page_content=content, metadata=meta)
    db.add_documents([doc])
    return f"Logged successful attack ({len(content)} chars)."