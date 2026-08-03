# =============================================================================
# loader.py — Index knowledge base documents into ChromaDB
# =============================================================================
#
# LEARNING NOTE: WHAT IS RAG?
# RAG = Retrieval-Augmented Generation. Instead of asking an LLM to answer
# from memory (which can hallucinate), we:
#   1. Store our trusted knowledge as "embeddings" in a vector database
#   2. When a question comes in, RETRIEVE the most relevant documents
#   3. Feed those documents to the LLM as context
#   4. The LLM GENERATES an answer grounded in real sources
#
# This file handles step 1: taking our Markdown knowledge base files,
# splitting them into chunks, converting them to embeddings, and storing
# them in ChromaDB.
#
# WHAT IS AN EMBEDDING?
# An embedding is a list of numbers (a "vector") that captures the
# *meaning* of a piece of text. Similar texts have similar vectors.
# For example, "RFID card" and "identification tag" would have vectors
# pointing in similar directions, even though the words are different.
#
# ChromaDB handles the embedding automatically using a built-in model
# (all-MiniLM-L6-v2), so we just give it text and it does the math.
# =============================================================================

from pathlib import Path
from typing import Optional

import chromadb
from chromadb.config import Settings


# ---- Constants ----

# Where our knowledge base documents live on disk
DEFAULT_KB_DIR = Path(__file__).parent.parent.parent.parent / "data" / "knowledge_base"

# Where ChromaDB will persist its data (so we don't re-index every time)
DEFAULT_DB_DIR = Path(__file__).parent.parent.parent.parent / "data" / "chroma_db"

# Name of the ChromaDB collection (like a "table" in a regular database)
COLLECTION_NAME = "ocpp_sentinel_kb"

# ---- Chunking Configuration ----
# We split documents into chunks because:
# 1. Embedding models have a maximum input length (typically 512 tokens)
# 2. Smaller chunks = more precise retrieval (we find the EXACT paragraph
#    that answers the question, not just "somewhere in this 5-page doc")
#
# These values control how we split:
CHUNK_SIZE = 500        # Target characters per chunk
CHUNK_OVERLAP = 100     # Characters of overlap between consecutive chunks
                        # (overlap prevents cutting a sentence in half)


def load_markdown_files(kb_dir: Path) -> list[dict]:
    """
    Recursively find all .md files in the knowledge base directory and
    load their content.

    LEARNING NOTE:
    Path.rglob("*.md") recursively searches all subdirectories for files
    matching the pattern "*.md". The 'r' in rglob stands for 'recursive'.

    Args:
        kb_dir: Path to the knowledge base directory.

    Returns:
        A list of dicts, each with 'content', 'source', and 'category' keys.
    """
    documents = []

    for md_file in sorted(kb_dir.rglob("*.md")):
        # Read the file content
        content = md_file.read_text(encoding="utf-8")

        # Determine the category from the parent directory name
        # e.g., "attacks/01_spoofing.md" → category = "attacks"
        category = md_file.parent.name

        documents.append({
            "content": content,
            "source": md_file.name,          # e.g., "01_spoofing.md"
            "category": category,             # e.g., "attacks" or "spec_excerpts"
            "filepath": str(md_file),         # Full path for debugging
        })

    return documents


def split_into_chunks(
    documents: list[dict],
    chunk_size: int = CHUNK_SIZE,
    chunk_overlap: int = CHUNK_OVERLAP,
) -> tuple[list[str], list[dict], list[str]]:
    """
    Split documents into smaller chunks for embedding.

    LEARNING NOTE:
    We use LangChain's RecursiveCharacterTextSplitter, which is smart about
    splitting. It tries to split at natural boundaries in this order:
      1. Double newlines (paragraph breaks)
      2. Single newlines
      3. Spaces (word boundaries)
      4. Individual characters (last resort)

    This means it prefers to keep paragraphs together, only breaking them
    if they're too long.

    Args:
        documents: List of document dicts from load_markdown_files().
        chunk_size: Target size for each chunk in characters.
        chunk_overlap: Number of overlapping characters between chunks.

    Returns:
        A tuple of (texts, metadatas, ids) ready for ChromaDB.
        - texts: The text content of each chunk
        - metadatas: Metadata dict for each chunk (source, category, etc.)
        - ids: Unique ID for each chunk
    """
    from langchain_text_splitters import RecursiveCharacterTextSplitter

    # Create the splitter
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        # These are the boundary characters it tries to split at (in order):
        separators=["\n\n", "\n", " ", ""],
    )

    texts = []      # The actual text chunks
    metadatas = []  # Metadata for each chunk (source file, category, etc.)
    ids = []        # Unique IDs for ChromaDB

    for doc in documents:
        # Split this document's content into chunks
        chunks = splitter.split_text(doc["content"])

        for i, chunk in enumerate(chunks):
            texts.append(chunk)

            # Metadata travels WITH each chunk in ChromaDB, so when we
            # retrieve a chunk later, we know where it came from.
            metadatas.append({
                "source": doc["source"],
                "category": doc["category"],
                "chunk_index": i,
                "total_chunks": len(chunks),
            })

            # IDs must be unique across the entire collection.
            # Format: "attacks/01_spoofing.md_chunk_0"
            ids.append(f"{doc['category']}/{doc['source']}_chunk_{i}")

    return texts, metadatas, ids


def index_knowledge_base(
    kb_dir: Optional[Path] = None,
    db_dir: Optional[Path] = None,
    force_reindex: bool = False,
) -> chromadb.Collection:
    """
    Load knowledge base documents, split them into chunks, and index them
    into ChromaDB.

    LEARNING NOTE:
    ChromaDB can persist data to disk (PersistentClient). This means:
    - First run: documents are loaded, embedded, and stored (~30 seconds)
    - Subsequent runs: data is loaded from disk instantly
    - Set force_reindex=True to rebuild from scratch (e.g., after editing docs)

    Args:
        kb_dir: Path to the knowledge base directory. Defaults to data/knowledge_base/.
        db_dir: Path to ChromaDB storage directory. Defaults to data/chroma_db/.
        force_reindex: If True, delete existing collection and re-index.

    Returns:
        The ChromaDB collection, ready for querying.
    """
    kb_dir = kb_dir or DEFAULT_KB_DIR
    db_dir = db_dir or DEFAULT_DB_DIR

    # Create the ChromaDB client with persistent storage
    # PersistentClient saves to disk so we don't re-embed every time
    client = chromadb.PersistentClient(
        path=str(db_dir),
        settings=Settings(
            anonymized_telemetry=False,  # Don't send usage data
        ),
    )

    # If force_reindex, delete the existing collection
    if force_reindex:
        try:
            client.delete_collection(COLLECTION_NAME)
            print(f"🗑️  Deleted existing collection '{COLLECTION_NAME}'")
        except ValueError:
            pass  # Collection didn't exist, that's fine

    # Get or create the collection
    # ChromaDB's default embedding function uses all-MiniLM-L6-v2,
    # a small but effective model that runs locally (no API key needed!)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={
            "description": "OCPP Sentinel security knowledge base",
            "hnsw:space": "cosine",  # Use cosine similarity for matching
        },
    )

    # Check if already indexed (skip if collection has documents)
    if collection.count() > 0 and not force_reindex:
        print(f"✅ Collection '{COLLECTION_NAME}' already has {collection.count()} chunks. Skipping indexing.")
        print("   (Use force_reindex=True to rebuild)")
        return collection

    # ---- Step 1: Load documents ----
    print(f"📂 Loading documents from: {kb_dir}")
    documents = load_markdown_files(kb_dir)
    print(f"   Found {len(documents)} documents")

    if not documents:
        print("⚠️  No documents found! Check the knowledge base directory.")
        return collection

    # ---- Step 2: Split into chunks ----
    print(f"✂️  Splitting into chunks (size={CHUNK_SIZE}, overlap={CHUNK_OVERLAP})")
    texts, metadatas, ids = split_into_chunks(documents)
    print(f"   Created {len(texts)} chunks")

    # ---- Step 3: Add to ChromaDB ----
    # ChromaDB automatically computes embeddings for each text chunk
    # using its default embedding model.
    print(f"🧠 Indexing {len(texts)} chunks into ChromaDB...")

    # ChromaDB has a batch size limit, so we add in batches
    BATCH_SIZE = 100
    for i in range(0, len(texts), BATCH_SIZE):
        batch_end = min(i + BATCH_SIZE, len(texts))
        collection.add(
            documents=texts[i:batch_end],
            metadatas=metadatas[i:batch_end],
            ids=ids[i:batch_end],
        )

    print(f"✅ Successfully indexed {collection.count()} chunks into '{COLLECTION_NAME}'")

    # Print a summary of what was indexed
    print("\n📊 Index Summary:")
    for doc in documents:
        print(f"   [{doc['category']}] {doc['source']}")

    return collection


# =============================================================================
# MAIN — Run this file directly to index the knowledge base
# =============================================================================
#
# LEARNING NOTE:
# The `if __name__ == "__main__"` pattern means this code ONLY runs when
# you execute this file directly (python -m ocpp_sentinel.knowledge.loader),
# NOT when it's imported by other code.
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("OCPP Sentinel — Knowledge Base Indexer")
    print("=" * 60)
    print()

    collection = index_knowledge_base(force_reindex=True)

    print()
    print("=" * 60)
    print("Done! The knowledge base is ready for retrieval.")
    print(f"Total chunks indexed: {collection.count()}")
    print("=" * 60)
