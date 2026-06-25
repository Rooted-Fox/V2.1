"""Shared state that flows between all LangGraph agents."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict


class AgentState(TypedDict, total=False):
    # Target
    target_url: str
    app_name: str
    final_url: str  # after redirect following

    # Recon outputs
    subdomains: List[str]
    endpoints: List[str]
    technologies: List[Dict[str, Any]]  # [{name, version, eol, cve_count}]
    js_files: List[str]
    forms: List[Dict[str, Any]]  # [{url, method, fields}]
    api_endpoints: List[str]
    hidden_params: Dict[str, List[str]]  # {url: [param1, param2]}

    # Auth outputs
    sessions: Dict[str, str]  # {role: session_cookie_or_token}
    default_creds_found: List[Dict[str, str]]  # [{url, username, password, tech}]
    auth_weaknesses: List[Dict[str, Any]]

    # Exploitation outputs
    raw_findings: List[Dict[str, Any]]
    sqli_findings: List[Dict[str, Any]]
    xss_findings: List[Dict[str, Any]]
    idor_findings: List[Dict[str, Any]]
    privesc_findings: List[Dict[str, Any]]
    info_disclosure_findings: List[Dict[str, Any]]
    eol_findings: List[Dict[str, Any]]

    # Validation outputs
    validated_findings: List[Dict[str, Any]]

    # Report
    attack_chains: List[Dict[str, Any]]
    report: Optional[str]

    # Control
    errors: List[str]
    current_agent: str
    iteration: int
