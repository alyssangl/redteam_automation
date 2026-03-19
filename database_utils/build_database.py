import os
import sys
import shutil
import argparse
import yaml
import csv
import dotenv
from typing import List, Dict, Any
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter, MarkdownHeaderTextSplitter, Language
from langchain_core.documents import Document

# --- 1. CONFIGURATION ---
DB_BASE_DIR = "../databases"
SOURCE_DOCS_DIR = "documents"

# YAML Config
YAML_SPLIT_AT_BRANCH = "atomic_tests"

# OpenAI Settings
dotenv.load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "text-embedding-3-small"


# --- 2. SPECIALIZED LOADERS ---
def load_markdown(filepath: str) -> List[Document]:
    """
    Handles Markdown files using header-based splitting.
    This keeps sections (Header -> Content) together semantically.
    """
    print(f"  [MD] Processing {os.path.basename(filepath)}")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            text = f.read()

        # Split by headers to preserve structure
        headers_to_split_on = [
            ("#", "Header 1"),
            ("##", "Header 2"),
            ("###", "Header 3"),
        ]
        markdown_splitter = MarkdownHeaderTextSplitter(headers_to_split_on=headers_to_split_on)
        md_header_splits = markdown_splitter.split_text(text)

        # UPDATED: Increased chunk size to 3000 to prevent fragmenting code blocks/logs
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=3000, chunk_overlap=500)
        final_docs = text_splitter.split_documents(md_header_splits)

        # Add Metadata and Re-inject Headers into Content
        for doc in final_docs:
            doc.metadata["source"] = os.path.basename(filepath)
            doc.metadata["type"] = "metasploit_doc"

            # Re-inject header context into the actual text content
            # This ensures the embedding vector includes the section title even after splitting
            header_path = []
            for key in ["Header 1", "Header 2", "Header 3"]:
                if key in doc.metadata:
                    header_path.append(doc.metadata[key])

            if header_path:
                # Prepend context: "Section: Description > Usage Example"
                context_str = " > ".join(header_path)
                doc.page_content = f"Section: {context_str}\n\n{doc.page_content}"

        return final_docs

    except Exception as e:
        print(f"Error loading MD {filepath}: {e}")
        return []

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
        ".yml": load_yaml,
        ".md": load_markdown
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


# --- 4. DATABASE MANAGEMENT FUNCTIONS ---

def get_db_path(name: str) -> str:
    return os.path.join(DB_BASE_DIR, name)


def get_embeddings():
    return OpenAIEmbeddings(model=OPENAI_MODEL, api_key=OPENAI_API_KEY)


def init_database(name: str) -> Chroma:
    """Create a new empty database. Wipes if it already exists."""
    db_path = get_db_path(name)
    if os.path.exists(db_path):
        shutil.rmtree(db_path)
    os.makedirs(db_path, exist_ok=True)
    return Chroma(persist_directory=db_path, embedding_function=get_embeddings(),
                  collection_name="my_rag_collection")


def open_database(name: str) -> Chroma:
    """Open an existing database (no wipe)."""
    db_path = get_db_path(name)
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database '{name}' not found at {db_path}")
    return Chroma(persist_directory=db_path, embedding_function=get_embeddings(),
                  collection_name="my_rag_collection")


def add_documents(vector_db: Chroma, docs: List[Document], batch_size: int = 100):
    """Batch-add Document objects to a ChromaDB instance."""
    for i in range(0, len(docs), batch_size):
        batch = docs[i:i + batch_size]
        vector_db.add_documents(batch)
        print(f"  Added batch {i}-{i + len(batch)}")
    print(f"Added {len(docs)} documents total.")


def add_file(vector_db: Chroma, filepath: str) -> int:
    """Ingest a single file using the appropriate loader. Returns chunk count."""
    ext = os.path.splitext(filepath)[1].lower()
    LOADER_REGISTRY = {".pdf": load_pdf, ".csv": load_csv,
                       ".yaml": load_yaml, ".yml": load_yaml, ".md": load_markdown}
    loader_func = LOADER_REGISTRY.get(ext)
    if not loader_func:
        print(f"Unsupported file type: {ext}")
        return 0
    docs = loader_func(filepath)
    if docs:
        add_documents(vector_db, docs)
    return len(docs)


def clean_database(name: str):
    """Delete a database entirely."""
    db_path = get_db_path(name)
    if os.path.exists(db_path):
        shutil.rmtree(db_path)
        print(f"Deleted database '{name}'.")
    else:
        print(f"Database '{name}' not found.")


# --- 5. CLI ---

def main():
    parser = argparse.ArgumentParser(description="RAG Knowledge Base Manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # newdb
    p_new = subparsers.add_parser("newdb", help="Create a new empty database")
    p_new.add_argument("name", help="Database name")

    # add
    p_add = subparsers.add_parser("add", help="Add file(s) to an existing database")
    p_add.add_argument("name", help="Database name")
    p_add.add_argument("files", nargs="+", help="File paths to ingest")

    # clean
    p_clean = subparsers.add_parser("clean", help="Delete a database")
    p_clean.add_argument("name", help="Database name to delete")

    # ingest (bulk add from directory — replaces old main behavior)
    p_ingest = subparsers.add_parser("ingest", help="Ingest all files from a directory into a database")
    p_ingest.add_argument("name", help="Database name")
    p_ingest.add_argument("--source", default=SOURCE_DOCS_DIR, help="Source directory (default: ./documents)")

    args = parser.parse_args()

    if not OPENAI_API_KEY:
        print("ERROR: OPENAI_API_KEY not found.")
        sys.exit(1)

    if args.command == "newdb":
        init_database(args.name)
        print(f"Created empty database '{args.name}' at {get_db_path(args.name)}")

    elif args.command == "add":
        db = open_database(args.name)
        for filepath in args.files:
            if not os.path.exists(filepath):
                print(f"File not found: {filepath}")
                continue
            count = add_file(db, filepath)
            print(f"  {filepath}: {count} chunks")

    elif args.command == "clean":
        clean_database(args.name)

    elif args.command == "ingest":
        try:
            db = open_database(args.name)
        except FileNotFoundError:
            db = init_database(args.name)
        docs = ingest_directory(args.source)
        if docs:
            add_documents(db, docs)
        print("Ingestion complete.")


if __name__ == "__main__":
    main()