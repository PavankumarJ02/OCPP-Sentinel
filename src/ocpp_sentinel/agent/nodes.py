# =============================================================================
# agent/nodes.py — LangGraph Node Functions (detect → retrieve → reason)
# =============================================================================

import os
from typing import Optional, Any
from pydantic import ValidationError

from ocpp_sentinel.models import OCPPMessage
from ocpp_sentinel.detectors import DetectorDispatcher, DetectionResult
from ocpp_sentinel.knowledge import KnowledgeBaseRetriever
from ocpp_sentinel.agent.state import AgentState, VerdictResponse


# Initialize shared dispatcher & retriever
dispatcher = DetectorDispatcher()
_retriever: Optional[KnowledgeBaseRetriever] = None


def get_retriever() -> KnowledgeBaseRetriever:
    """Lazy load KnowledgeBaseRetriever to handle unindexed DB gracefully."""
    global _retriever
    if _retriever is None:
        _retriever = KnowledgeBaseRetriever()
    return _retriever


# =============================================================================
# NODE 1: DETECT
# =============================================================================

def detect_node(state: AgentState) -> dict[str, Any]:
    """
    Node 1: Parse incoming message and run rule-based security detectors.
    """
    raw_message = state.get("raw_message", {})
    
    try:
        # Strip metadata/comments if present
        msg_dict = {k: v for k, v in raw_message.items() if not k.startswith("_")}
        message = OCPPMessage(**msg_dict)
    except ValidationError as e:
        return {
            "error": f"Validation Error: Invalid OCPP message structure. {str(e)}",
            "verdict": VerdictResponse(
                verdict="suspicious",
                matched_attack_category="Malformed Input",
                confidence=1.0,
                plain_english_reason=f"Failed message validation: {e.errors()[0].get('msg', 'Invalid schema')}",
                source_reference="OCPP 1.6-J Base Message Specification",
                rule_detected=True,
            )
        }

    # Run deterministic detectors
    detection_result = dispatcher.get_first_detection(message)

    return {
        "message": message,
        "detection_result": detection_result,
    }


# =============================================================================
# NODE 2: RETRIEVE
# =============================================================================

def retrieve_node(state: AgentState) -> dict[str, Any]:
    """
    Node 2: Retrieve relevant attack documentation & spec excerpts from ChromaDB.
    """
    if state.get("error"):
        return {}

    message: Optional[OCPPMessage] = state.get("message")
    detection: Optional[DetectionResult] = state.get("detection_result")

    if not message:
        return {"retrieved_attacks": [], "retrieved_specs": []}

    retriever = get_retriever()

    # Formulate query text based on rule detection or message content
    if detection and detection.detected and detection.suggested_query:
        query_text = detection.suggested_query
    else:
        # Default contextual query based on message action
        query_text = f"{message.action.value} security analysis authorization specification"

    # Fetch top matches for both categories
    combined = retriever.query_combined(query_text, n_attack_results=2, n_spec_results=2)

    retrieved_attacks = [
        {"text": r.text, "source": r.source, "score": r.relevance_score}
        for r in combined.get("attacks", [])
    ]
    retrieved_specs = [
        {"text": r.text, "source": r.source, "score": r.relevance_score}
        for r in combined.get("specs", []) or combined.get("spec_excerpts", [])
    ]

    return {
        "retrieved_attacks": retrieved_attacks,
        "retrieved_specs": retrieved_specs,
    }


# =============================================================================
# NODE 3: REASON
# =============================================================================

def reason_node(state: AgentState) -> dict[str, Any]:
    """
    Node 3: Synthesize detection findings and vector RAG context into a final verdict.
    Uses LLM (OpenAI / Anthropic) if API keys are set, or grounded RAG synthesis.
    """
    if state.get("error"):
        return {}

    message: Optional[OCPPMessage] = state.get("message")
    detection: Optional[DetectionResult] = state.get("detection_result")
    attacks = state.get("retrieved_attacks", [])
    specs = state.get("retrieved_specs", [])

    if not message:
        return {}

    # Check for available LLM keys
    openai_key = os.getenv("OPENAI_API_KEY")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")

    if openai_key or anthropic_key:
        verdict = _reason_with_llm(message, detection, attacks, specs, openai_key, anthropic_key)
    else:
        verdict = _reason_with_rag_fallback(message, detection, attacks, specs)

    return {"verdict": verdict}


def _reason_with_rag_fallback(
    message: OCPPMessage,
    detection: Optional[DetectionResult],
    attacks: list[dict],
    specs: list[dict],
) -> VerdictResponse:
    """
    Grounded reasoning fallback when running offline / without an LLM API key.
    Uses detector results and retrieved ChromaDB sources.
    """
    if detection and detection.detected:
        # Determine source reference from RAG or spec
        spec_source = specs[0]["source"] if specs else f"OCPP 1.6-J Section for {message.action.value}"
        attack_source = attacks[0]["source"] if attacks else f"{detection.attack_category} Research Document"
        source_ref = f"{spec_source} / {attack_source}"

        return VerdictResponse(
            verdict="suspicious",
            matched_attack_category=detection.attack_category,
            confidence=detection.confidence,
            plain_english_reason=detection.details,
            source_reference=source_ref,
            rule_detected=True,
        )

    # Benign case
    spec_source = specs[0]["source"] if specs else "OCPP 1.6-J Standard"
    return VerdictResponse(
        verdict="normal",
        matched_attack_category="None",
        confidence=0.95,
        plain_english_reason=f"Message '{message.action.value}' (ID: {message.unique_id}) passed all rule-based checks with normal operational parameters.",
        source_reference=spec_source,
        rule_detected=False,
    )


def _reason_with_llm(
    message: OCPPMessage,
    detection: Optional[DetectionResult],
    attacks: list[dict],
    specs: list[dict],
    openai_key: Optional[str],
    anthropic_key: Optional[str],
) -> VerdictResponse:
    """
    Call OpenAI or Anthropic using LangChain structured output.
    """
    prompt = f"""You are OCPP Sentinel, an AI security triage copilot for EV charging stations.
Analyze the following OCPP message and return a structured verdict.

Message Action: {message.action.value}
Charge Point ID: {message.charge_point_id}
Payload: {message.payload}
Context: {message.context.model_dump()}

Rule-Based Detection Result:
Detected: {detection.detected if detection else False}
Rule Category: {detection.attack_category if detection else 'None'}
Rule Details: {detection.details if detection else 'None'}

Retrieved Knowledge Base Context:
Attack Docs: {[a['source'] + ': ' + a['text'][:200] for a in attacks]}
Spec Excerpts: {[s['source'] + ': ' + s['text'][:200] for s in specs]}

Your task: Return a JSON verdict with:
- verdict: 'normal' or 'suspicious'
- matched_attack_category: 'Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', or 'None'
- confidence: float between 0.0 and 1.0
- plain_english_reason: clear, detailed, accessible explanation citing specific payload anomaly
- source_reference: citation of relevant knowledge base file / spec section
- rule_detected: boolean
"""

    try:
        if openai_key:
            from langchain_openai import ChatOpenAI
            llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.0)
        else:
            from langchain_anthropic import ChatAnthropic
            llm = ChatAnthropic(model="claude-3-haiku-20240307", temperature=0.0)

        structured_llm = llm.with_structured_output(VerdictResponse)
        verdict = structured_llm.invoke(prompt)
        return verdict
    except Exception:
        # Fallback to grounded synthesis if LLM API call fails
        return _reason_with_rag_fallback(message, detection, attacks, specs)
