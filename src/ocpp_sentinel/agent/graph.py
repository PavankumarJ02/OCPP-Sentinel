# =============================================================================
# agent/graph.py — LangGraph State Machine Definition
# =============================================================================

from typing import Any
from langgraph.graph import StateGraph, END

from ocpp_sentinel.agent.state import AgentState, VerdictResponse
from ocpp_sentinel.agent.nodes import detect_node, retrieve_node, reason_node


def build_agent_graph() -> Any:
    """
    Construct and compile the LangGraph agent state graph.

    Graph Architecture:
        [START] → detect → retrieve → reason → [END]
    """
    workflow = StateGraph(AgentState)

    # Add nodes
    workflow.add_node("detect", detect_node)
    workflow.add_node("retrieve", retrieve_node)
    workflow.add_node("reason", reason_node)

    # Define simple sequential edges
    workflow.set_entry_point("detect")
    workflow.add_edge("detect", "retrieve")
    workflow.add_edge("retrieve", "reason")
    workflow.add_edge("reason", END)

    # Compile the graph
    app = workflow.compile()
    return app


# Shared compiled graph instance
_agent_app = None


def get_agent_app() -> Any:
    global _agent_app
    if _agent_app is None:
        _agent_app = build_agent_graph()
    return _agent_app


def run_sentinel_agent(raw_message: dict[str, Any]) -> VerdictResponse:
    """
    Execute the agent graph end-to-end on an incoming raw OCPP JSON message.

    Args:
        raw_message: The raw OCPP JSON dict.

    Returns:
        VerdictResponse object containing verdict, category, explanation, and sources.
    """
    app = get_agent_app()
    initial_state: AgentState = {"raw_message": raw_message}

    final_state = app.invoke(initial_state)

    verdict = final_state.get("verdict")
    if not verdict:
        # Fallback error verdict if state graph produced no verdict
        error_msg = final_state.get("error", "Unknown processing error")
        verdict = VerdictResponse(
            verdict="suspicious",
            matched_attack_category="Error",
            confidence=0.0,
            plain_english_reason=f"Processing failed: {error_msg}",
            source_reference="System Error",
            rule_detected=False,
        )

    return verdict
