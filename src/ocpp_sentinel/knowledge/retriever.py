# =============================================================================
# retriever.py — Query the ChromaDB knowledge base
# =============================================================================
#
# LEARNING NOTE: HOW VECTOR SEARCH WORKS
# When you search a vector database, you're NOT doing keyword matching
# (like Ctrl+F). Instead:
#   1. Your query text is converted to an embedding vector
#   2. ChromaDB finds the stored vectors that are CLOSEST to your query
#      vector (using cosine similarity)
#   3. It returns the corresponding text chunks
#
# This means searching for "fake RFID tag attack" will find documents
# about "spoofing via unauthorized idTag" even though the words are
# completely different — because the MEANING is similar.
#
# COSINE SIMILARITY:
# Ranges from -1 (opposite) to 1 (identical). In ChromaDB, distances
# are returned as (1 - cosine_similarity), so:
#   - Distance 0.0 = perfect match
#   - Distance 1.0 = completely unrelated
#   - Distance < 0.5 = usually relevant
# =============================================================================

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import chromadb
from chromadb.config import Settings

from ocpp_sentinel.knowledge.loader import (
    COLLECTION_NAME,
    DEFAULT_DB_DIR,
)


@dataclass
class RetrievalResult:
    """
    A single result from a knowledge base query.

    LEARNING NOTE:
    @dataclass is Python's way of creating simple classes that hold data.
    It automatically generates __init__, __repr__, and __eq__ methods.
    Think of it as a lightweight alternative to Pydantic's BaseModel —
    less validation, but simpler for internal data structures.
    """
    text: str           # The retrieved text chunk
    source: str         # Which file this came from (e.g., "01_spoofing.md")
    category: str       # "attacks" or "spec_excerpts"
    distance: float     # How close the match is (0 = perfect, 1 = unrelated)
    chunk_index: int    # Which chunk of the source document this is

    @property
    def relevance_score(self) -> float:
        """
        Convert distance to a 0-1 relevance score (1 = most relevant).

        LEARNING NOTE:
        @property makes this method accessible like an attribute:
            result.relevance_score  (not result.relevance_score())
        This is a Pythonic way to compute derived values.
        """
        return max(0.0, 1.0 - self.distance)


class KnowledgeBaseRetriever:
    """
    Queries the ChromaDB knowledge base to find relevant attack descriptions
    and OCPP spec excerpts.

    LEARNING NOTE:
    This class follows the "Repository Pattern" — it hides the details of
    HOW data is stored (ChromaDB) and exposes a simple interface for
    WHAT you can do with it (query for relevant documents).

    Usage:
        retriever = KnowledgeBaseRetriever()
        results = retriever.query("unauthorized RFID tag starting a session")
        for result in results:
            print(f"{result.source}: {result.text[:100]}...")
    """

    def __init__(self, db_dir: Optional[Path] = None):
        """
        Connect to the ChromaDB collection.

        Args:
            db_dir: Path to ChromaDB storage. Defaults to data/chroma_db/.

        Raises:
            RuntimeError: If the knowledge base hasn't been indexed yet.
        """
        db_dir = db_dir or DEFAULT_DB_DIR

        # Connect to the persistent ChromaDB client
        self._client = chromadb.PersistentClient(
            path=str(db_dir),
            settings=Settings(anonymized_telemetry=False),
        )

        # Get the collection (it must already exist from the loader)
        try:
            self._collection = self._client.get_collection(COLLECTION_NAME)
        except ValueError:
            raise RuntimeError(
                f"Knowledge base collection '{COLLECTION_NAME}' not found. "
                "Run the loader first:\n"
                "  python -m ocpp_sentinel.knowledge.loader"
            )

    @property
    def document_count(self) -> int:
        """How many chunks are in the knowledge base."""
        return self._collection.count()

    def query(
        self,
        query_text: str,
        n_results: int = 5,
        category_filter: Optional[str] = None,
    ) -> list[RetrievalResult]:
        """
        Search the knowledge base for documents relevant to the query.

        LEARNING NOTE:
        This is the core of RAG retrieval. We send a natural language query,
        and ChromaDB finds the most semantically similar chunks. We can
        optionally filter by category ("attacks" or "spec_excerpts") to
        narrow the search.

        Args:
            query_text: Natural language query (e.g., "unauthorized charging session").
            n_results: Maximum number of results to return (default 5).
            category_filter: Optional filter — "attacks" or "spec_excerpts".

        Returns:
            List of RetrievalResult objects, sorted by relevance (most relevant first).
        """
        # Build the optional metadata filter
        # ChromaDB's where clause filters results BEFORE ranking
        where_filter = None
        if category_filter:
            where_filter = {"category": category_filter}

        # Query ChromaDB — it handles embedding the query text automatically
        results = self._collection.query(
            query_texts=[query_text],      # What to search for
            n_results=n_results,           # How many results to return
            where=where_filter,            # Optional metadata filter
            include=["documents", "metadatas", "distances"],  # What to return
        )

        # ---- Unpack the results ----
        # ChromaDB returns results in a nested structure:
        #   results["documents"][0] = list of document texts
        #   results["metadatas"][0] = list of metadata dicts
        #   results["distances"][0] = list of distance scores
        # The [0] is because we only sent one query (query_texts has one item).

        retrieval_results = []

        # zip() combines multiple lists element-by-element:
        # zip([a,b], [1,2], [x,y]) → [(a,1,x), (b,2,y)]
        for doc, metadata, distance in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            retrieval_results.append(
                RetrievalResult(
                    text=doc,
                    source=metadata["source"],
                    category=metadata["category"],
                    distance=distance,
                    chunk_index=metadata["chunk_index"],
                )
            )

        return retrieval_results

    def query_for_attack(self, query_text: str, n_results: int = 3) -> list[RetrievalResult]:
        """
        Search only the attack description documents.
        Convenience method that filters to category="attacks".
        """
        return self.query(query_text, n_results=n_results, category_filter="attacks")

    def query_for_spec(self, query_text: str, n_results: int = 3) -> list[RetrievalResult]:
        """
        Search only the OCPP spec excerpt documents.
        Convenience method that filters to category="spec_excerpts".
        """
        return self.query(query_text, n_results=n_results, category_filter="spec_excerpts")

    def query_combined(
        self,
        query_text: str,
        n_attack_results: int = 2,
        n_spec_results: int = 2,
    ) -> dict[str, list[RetrievalResult]]:
        """
        Search both attack descriptions AND spec excerpts, returning
        results grouped by category.

        This is the method the agent will primarily use — it needs BOTH
        the attack description (to classify the threat) and the spec
        excerpt (to cite the relevant section).

        Args:
            query_text: Natural language query.
            n_attack_results: How many attack docs to retrieve.
            n_spec_results: How many spec docs to retrieve.

        Returns:
            Dict with "attacks" and "spec_excerpts" keys, each containing
            a list of RetrievalResult objects.
        """
        return {
            "attacks": self.query_for_attack(query_text, n_results=n_attack_results),
            "spec_excerpts": self.query_for_spec(query_text, n_results=n_spec_results),
        }
