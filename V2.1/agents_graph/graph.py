"""LangGraph workflow definition — connects all six agents into a stateful graph.

Flow:
  recon → auth → exploitation → validation → report

LangGraph is used when installed. Falls back to sequential execution
if LangGraph is not available, so the platform still works without it.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from agents_graph.state import AgentState
from agents_graph.recon_agent import run_recon
from agents_graph.auth_agent import run_auth
from agents_graph.exploitation_agent import run_exploitation
from agents_graph.validation_agent import run_validation


def _sequential_run(initial_state: AgentState) -> AgentState:
    """Fallback: run all agents sequentially without LangGraph."""
    state = initial_state
    for fn in [run_recon, run_auth, run_exploitation, run_validation]:
        try:
            state = fn(state)
        except Exception as e:
            state = {**state, "errors": state.get("errors", []) + [f"{fn.__name__}: {e}"]}
    return state


def build_graph():
    """Build and return the LangGraph StateGraph if available."""
    try:
        from langgraph.graph import StateGraph, END

        def recon_node(state):   return run_recon(state)
        def auth_node(state):    return run_auth(state)
        def exploit_node(state): return run_exploitation(state)
        def validate_node(state):return run_validation(state)

        g = StateGraph(AgentState)
        g.add_node("recon",       recon_node)
        g.add_node("auth",        auth_node)
        g.add_node("exploitation",exploit_node)
        g.add_node("validation",  validate_node)

        g.set_entry_point("recon")
        g.add_edge("recon",        "auth")
        g.add_edge("auth",         "exploitation")
        g.add_edge("exploitation", "validation")
        g.add_edge("validation",   END)

        return g.compile()
    except ImportError:
        return None


def run_agent_pipeline(target_url: str, app_name: str,
                       progress_callback=None) -> Dict[str, Any]:
    """Run the full agent pipeline. Returns the final state."""
    initial_state: AgentState = {
        "target_url": target_url,
        "app_name": app_name,
        "final_url": target_url,
        "subdomains": [],
        "endpoints": [],
        "technologies": [],
        "js_files": [],
        "forms": [],
        "api_endpoints": [],
        "hidden_params": {},
        "sessions": {},
        "default_creds_found": [],
        "auth_weaknesses": [],
        "raw_findings": [],
        "sqli_findings": [],
        "xss_findings": [],
        "idor_findings": [],
        "privesc_findings": [],
        "info_disclosure_findings": [],
        "eol_findings": [],
        "validated_findings": [],
        "attack_chains": [],
        "report": None,
        "errors": [],
        "current_agent": "",
        "iteration": 0,
    }

    graph = build_graph()
    if graph:
        result = graph.invoke(initial_state)
    else:
        result = _sequential_run(initial_state)

    return dict(result)
