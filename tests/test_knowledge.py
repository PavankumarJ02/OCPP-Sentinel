# =============================================================================
# test_knowledge.py — Tests for the knowledge base loader and retriever
# =============================================================================
#
# LEARNING NOTE:
# These tests verify that:
# 1. Our knowledge base documents load correctly from disk
# 2. ChromaDB indexes them without errors
# 3. Semantic search returns relevant results for each attack type
# 4. Category filtering works (attacks vs. spec_excerpts)
#
# IMPORTANT: These tests create a TEMPORARY ChromaDB database in a temp
# directory (not the main data/chroma_db). This prevents tests from
# interfering with your real knowledge base.
# =============================================================================

import shutil
from pathlib import Path

import pytest

from ocpp_sentinel.knowledge.loader import (
    load_markdown_files,
    split_into_chunks,
    index_knowledge_base,
    DEFAULT_KB_DIR,
)
from ocpp_sentinel.knowledge.retriever import KnowledgeBaseRetriever


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(scope="module")
def test_db_dir(tmp_path_factory) -> Path:
    """
    Create a temporary directory for the test ChromaDB database.

    LEARNING NOTE:
    scope="module" means this fixture is created ONCE for all tests in
    this file (not once per test). This is important because indexing
    takes a few seconds — we don't want to redo it for every test.

    tmp_path_factory is a pytest built-in that creates temp directories
    that are automatically cleaned up after tests finish.
    """
    return tmp_path_factory.mktemp("test_chroma_db")


@pytest.fixture(scope="module")
def indexed_collection(test_db_dir: Path):
    """
    Index the knowledge base into a test ChromaDB instance.
    This runs once and is shared across all tests in this module.
    """
    collection = index_knowledge_base(
        kb_dir=DEFAULT_KB_DIR,
        db_dir=test_db_dir,
        force_reindex=True,
    )
    return collection


@pytest.fixture(scope="module")
def retriever(test_db_dir: Path, indexed_collection) -> KnowledgeBaseRetriever:
    """
    Create a retriever connected to the test ChromaDB instance.
    Depends on indexed_collection to ensure indexing happens first.
    """
    return KnowledgeBaseRetriever(db_dir=test_db_dir)


# =============================================================================
# TEST: Document loading
# =============================================================================

def test_load_markdown_files():
    """All knowledge base Markdown files should load successfully."""
    documents = load_markdown_files(DEFAULT_KB_DIR)

    # We should have 10 documents: 5 attacks + 5 spec excerpts
    assert len(documents) == 10

    # Check that we have both categories
    categories = {doc["category"] for doc in documents}
    assert "attacks" in categories
    assert "spec_excerpts" in categories

    # Each document should have non-empty content
    for doc in documents:
        assert len(doc["content"]) > 0, f"Empty document: {doc['source']}"
        assert doc["source"].endswith(".md"), f"Not a .md file: {doc['source']}"


def test_split_into_chunks():
    """Documents should be split into reasonably-sized chunks."""
    documents = load_markdown_files(DEFAULT_KB_DIR)
    texts, metadatas, ids = split_into_chunks(documents)

    # We should have more chunks than documents (each doc gets split)
    assert len(texts) > len(documents)

    # All three lists should be the same length
    assert len(texts) == len(metadatas) == len(ids)

    # Each chunk should have metadata
    for metadata in metadatas:
        assert "source" in metadata
        assert "category" in metadata
        assert "chunk_index" in metadata

    # IDs should be unique
    assert len(set(ids)) == len(ids), "Duplicate chunk IDs found!"


# =============================================================================
# TEST: ChromaDB indexing
# =============================================================================

def test_collection_has_documents(indexed_collection):
    """The ChromaDB collection should contain indexed chunks."""
    assert indexed_collection.count() > 0
    print(f"\n  [INFO] Indexed {indexed_collection.count()} chunks")


# =============================================================================
# TEST: Semantic retrieval — each attack type should be findable
# =============================================================================

def test_retrieve_spoofing(retriever: KnowledgeBaseRetriever):
    """
    Querying about unauthorized remote start should find the spoofing attack.
    """
    results = retriever.query_for_attack(
        "RemoteStartTransaction with fake unauthorized idTag"
    )

    assert len(results) > 0

    top_source = results[0].source
    assert "spoofing" in top_source.lower(), (
        f"Expected spoofing doc, got: {top_source}"
    )

    assert results[0].relevance_score > 0.3, (
        f"Low relevance: {results[0].relevance_score:.2f}"
    )

    print(f"\n  [QUERY] 'unauthorized remote start'")
    print(f"     Top result: {top_source} (relevance: {results[0].relevance_score:.2f})")


def test_retrieve_tampering(retriever: KnowledgeBaseRetriever):
    """
    Querying about implausible meter readings should find the tampering attack.
    """
    results = retriever.query_for_attack(
        "MeterValues reporting very low energy billing fraud"
    )

    assert len(results) > 0
    top_source = results[0].source
    assert "tampering" in top_source.lower(), (
        f"Expected tampering doc, got: {top_source}"
    )
    print(f"\n  [QUERY] 'low energy billing fraud'")
    print(f"     Top result: {top_source} (relevance: {results[0].relevance_score:.2f})")


def test_retrieve_repudiation(retriever: KnowledgeBaseRetriever):
    """
    Querying about replayed messages should find the repudiation attack.
    """
    results = retriever.query_for_attack(
        "replayed Authorize message duplicate messageId"
    )

    assert len(results) > 0
    top_source = results[0].source
    assert "repudiation" in top_source.lower(), (
        f"Expected repudiation doc, got: {top_source}"
    )
    print(f"\n  [QUERY] 'replayed Authorize message'")
    print(f"     Top result: {top_source} (relevance: {results[0].relevance_score:.2f})")


def test_retrieve_info_disclosure(retriever: KnowledgeBaseRetriever):
    """
    Querying about sensitive data in logs should find the info disclosure attack.
    """
    results = retriever.query_for_attack(
        "Information disclosure token session key plaintext in info field diagnostic logs"
    )

    assert len(results) > 0
    # Check if info_disclosure is among the top retrieved attack docs
    sources = [r.source.lower() for r in results]
    assert any("info_disclosure" in src for src in sources), (
        f"Expected info_disclosure doc in results, got: {sources}"
    )
    print(f"\n  [QUERY] 'plaintext token in logs'")
    print(f"     Results: {sources}")


def test_retrieve_dos(retriever: KnowledgeBaseRetriever):
    """
    Querying about message floods should find the DoS attack.
    """
    results = retriever.query_for_attack(
        "flood of StatusNotification messages overwhelming the system"
    )

    assert len(results) > 0
    top_source = results[0].source
    assert "dos" in top_source.lower(), (
        f"Expected dos doc, got: {top_source}"
    )
    print(f"\n  [QUERY] 'StatusNotification flood'")
    print(f"     Top result: {top_source} (relevance: {results[0].relevance_score:.2f})")


# =============================================================================
# TEST: Spec excerpt retrieval
# =============================================================================

def test_retrieve_spec_for_remote_start(retriever: KnowledgeBaseRetriever):
    """
    Querying about RemoteStartTransaction should find the relevant spec excerpt.
    """
    results = retriever.query_for_spec(
        "RemoteStartTransaction request fields and security"
    )

    assert len(results) > 0
    top_source = results[0].source
    assert "remote_start" in top_source.lower(), (
        f"Expected remote_start_transaction spec, got: {top_source}"
    )
    print(f"\n  [SPEC] Query: 'RemoteStartTransaction spec'")
    print(f"     Top result: {top_source} (relevance: {results[0].relevance_score:.2f})")


def test_retrieve_spec_for_meter_values(retriever: KnowledgeBaseRetriever):
    """
    Querying about MeterValues should find the relevant spec excerpt.
    """
    results = retriever.query_for_spec(
        "MeterValues energy measurement billing sampled value"
    )

    assert len(results) > 0
    top_source = results[0].source
    assert "meter_values" in top_source.lower(), (
        f"Expected meter_values spec, got: {top_source}"
    )
    print(f"\n  [SPEC] Query: 'MeterValues billing spec'")
    print(f"     Top result: {top_source} (relevance: {results[0].relevance_score:.2f})")


# =============================================================================
# TEST: Combined query (attacks + specs together)
# =============================================================================

def test_combined_query(retriever: KnowledgeBaseRetriever):
    """
    The combined query should return both attack descriptions AND spec excerpts.
    This is what the agent will use in Phase 4.
    """
    results = retriever.query_combined(
        "unauthorized idTag in RemoteStartTransaction spoofing attack"
    )

    assert "attacks" in results
    assert "spec_excerpts" in results

    assert len(results["attacks"]) > 0
    assert len(results["spec_excerpts"]) > 0

    print(f"\n  [COMBINED] Query results:")
    print(f"     Attacks: {[r.source for r in results['attacks']]}")
    print(f"     Specs:   {[r.source for r in results['spec_excerpts']]}")


# =============================================================================
# TEST: Category filter works
# =============================================================================

def test_category_filter(retriever: KnowledgeBaseRetriever):
    """
    Filtering by category should only return results from that category.
    """
    attack_results = retriever.query(
        "OCPP security", category_filter="attacks"
    )
    spec_results = retriever.query(
        "OCPP security", category_filter="spec_excerpts"
    )

    for result in attack_results:
        assert result.category == "attacks", (
            f"Expected 'attacks', got '{result.category}'"
        )

    for result in spec_results:
        assert result.category == "spec_excerpts", (
            f"Expected 'spec_excerpts', got '{result.category}'"
        )


# =============================================================================
# TEST: Document count
# =============================================================================

def test_retriever_document_count(retriever: KnowledgeBaseRetriever):
    """The retriever should report the correct number of indexed chunks."""
    count = retriever.document_count
    assert count > 0
    print(f"\n  [INFO] Total chunks in knowledge base: {count}")
