import os
import shutil
import yaml
import csv
import dotenv
from typing import List, Dict, Any
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

# --- 1. CONFIGURATION ---
DB_PATH = "./my_knowledge_base"
SOURCE_DOCS_DIR = "./documents"

# YAML Config
YAML_SPLIT_AT_BRANCH = "atomic_tests"

# OpenAI Settings
dotenv.load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "text-embedding-3-small"


# --- 2. SPECIALIZED LOADERS ---

def load_pdf(filepath: str) -> List[Document]:
    """Handles PDF splitting and loading."""
    print(f"  [PDF] Processing {os.path.basename(filepath)}")
    loader = PyPDFLoader(filepath)
    raw_docs = loader.load()
    # PDFs always need splitting because pages are arbitrary
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    return splitter.split_documents(raw_docs)


def load_csv(filepath: str) -> List[Document]:
    """
    Handles CSVs with ANY structure.
    Strategy: Serialize every row into a 'Key: Value' text block.
    """
    print(f"  [CSV] Processing {os.path.basename(filepath)}")
    documents = []
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            # DictReader automatically picks up whatever headers exist in THIS file
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return []

            for i, row in enumerate(reader):
                # SERIALIZATION: Convert {"id": "1", "val": "A"} -> "id: 1\nval: A"
                # This creates a single text block for the LLM to read.
                content_parts = []
                for k, v in row.items():
                    if v and v.strip():  # Skip empty values
                        content_parts.append(f"{k}: {v.strip()}")

                text_content = "\n".join(content_parts)

                # Create Document
                doc = Document(
                    page_content=text_content,
                    metadata={
                        "source": os.path.basename(filepath),
                        "row": i,
                        "type": "csv_entry"
                    }
                )
                documents.append(doc)
    except Exception as e:
        print(f"Error loading CSV {filepath}: {e}")
    return documents


def load_yaml(filepath: str) -> List[Document]:
    """
    Handles YAML with generic splitting strategy.
    """
    print(f"  [YAML] Processing {os.path.basename(filepath)}")
    documents = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data_list = list(yaml.safe_load_all(f))

        for data in data_list:
            if not data: continue

            # Identify Context (Everything NOT in the split branch)
            shared_context = {k: v for k, v in data.items() if k != YAML_SPLIT_AT_BRANCH}

            # Check for split branch
            if YAML_SPLIT_AT_BRANCH in data and isinstance(data[YAML_SPLIT_AT_BRANCH], list):
                # Split the list items
                for i, item in enumerate(data[YAML_SPLIT_AT_BRANCH]):
                    chunk_data = shared_context.copy()
                    chunk_data[YAML_SPLIT_AT_BRANCH] = [item]

                    text_content = yaml.safe_dump(chunk_data, allow_unicode=True, sort_keys=False)

                    doc = Document(
                        page_content=text_content,
                        metadata={
                            "source": os.path.basename(filepath),
                            "split_index": i,
                            "type": "yaml_entry"
                        }
                    )
                    documents.append(doc)
            else:
                # Fallback: Whole file
                text_content = yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
                doc = Document(
                    page_content=text_content,
                    metadata={"source": os.path.basename(filepath)}
                )
                documents.append(doc)
    except Exception as e:
        print(f"Error loading YAML {filepath}: {e}")
    return documents


# --- 3. THE DISPATCHER (ROUTER) ---

def ingest_directory(directory: str) -> List[Document]:
    """
    Iterates through a directory and routes files to the correct loader.
    """
    all_documents = []

    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")
        return []

    print(f"Scanning {directory}...")

    # Map extensions to functions
    LOADER_REGISTRY = {
        ".pdf": load_pdf,
        ".csv": load_csv,
        ".yaml": load_yaml,
        ".yml": load_yaml
    }

    for root, dirs, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            ext = os.path.splitext(filename)[1].lower()

            if ext in LOADER_REGISTRY:
                # Call the specific loader function
                loader_func = LOADER_REGISTRY[ext]
                new_docs = loader_func(file_path)
                all_documents.extend(new_docs)
            else:
                print(f"  [SKIP] Unknown file type: {filename}")

    return all_documents


# --- 4. MAIN EXECUTION ---

def main():
    print(f"--- RAG Ingestion Engine ---")
    print(f"Model: {OPENAI_MODEL}")

    if not OPENAI_API_KEY:
        print("ERROR: OPENAI_API_KEY not found.")
        return

    embeddings = OpenAIEmbeddings(model=OPENAI_MODEL, api_key=OPENAI_API_KEY)

    # Clean previous DB
    if os.path.exists(DB_PATH):
        print(f"Resetting database at {DB_PATH}...")
        shutil.rmtree(DB_PATH)

    # 1. LOAD (Extract & Transform)
    docs = ingest_directory(SOURCE_DOCS_DIR)

    if not docs:
        print("No documents found.")
        return

    # 2. STORE (Load)
    print(f"Inserting {len(docs)} chunks into ChromaDB...")
    vector_db = Chroma(
        persist_directory=DB_PATH,
        embedding_function=embeddings,
        collection_name="my_rag_collection"
    )

    # Batch add (Chroma handles large batches better than one-by-one)
    BATCH_SIZE = 100
    for i in range(0, len(docs), BATCH_SIZE):
        batch = docs[i: i + BATCH_SIZE]
        vector_db.add_documents(batch)
        print(f"  Added batch {i}-{i + len(batch)}")

    print("Ingestion Complete.")


if __name__ == "__main__":
    main()