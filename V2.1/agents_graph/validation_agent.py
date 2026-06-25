"""Validation Agent — Opus-powered reasoning confirmation of all findings."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from agents_graph.state import AgentState
from agents.agent import _build_client
from runtime_settings import get_settings

_VALIDATION_SYSTEM = """You are a senior penetration tester validating security findings.

For each finding, determine:
1. Is this a genuine, exploitable vulnerability or a false positive?
2. What is the real-world business impact?
3. What is the exact remediation?
4. Does this connect to other findings to form a larger attack chain?

For each finding return a JSON object:
{
  "confirmed": true/false,
  "confidence": 0-100,
  "severity": "critical|high|medium|low",
  "cvss_score": 0.0-10.0,
  "cvss_vector": "CVSS:3.1/...",
  "cwe_id": "CWE-XX",
  "cwe_name": "...",
  "vulnerability_name": "concise professional name",
  "root_cause": "exact technical root cause",
  "business_impact": "real-world business consequences",
  "attack_scenario": "step-by-step attacker path",
  "reproduction_steps": "exact steps to reproduce",
  "remediation": "specific actionable fix",
  "false_positive_reason": "why dismissed if confirmed=false, else null"
}

Respond with a JSON array of exactly N objects matching the N input findings."""


def run_validation(state: AgentState) -> AgentState:
    """Validate all raw findings through Opus reasoning."""
    raw_findings = state.get("raw_findings", [])
    errors = list(state.get("errors", []))
    state = {**state, "current_agent": "validation"}

    if not raw_findings:
        return {**state, "validated_findings": []}

    rt = get_settings()
    if not rt.get("ai_enabled") or not rt.get("anthropic_api_key") and not rt.get("azure_foundry_api_key"):
        # Return raw findings without AI validation if AI not enabled
        return {**state, "validated_findings": raw_findings}

    try:
        client = _build_client(rt)
        model = rt["agent_model"]

        # Process in batches of 8
        validated = []
        for i in range(0, len(raw_findings), 8):
            batch = raw_findings[i:i+8]
            findings_text = json.dumps(batch, indent=2)
            user_msg = (
                f"Validate these {len(batch)} security findings from an authorized "
                f"penetration test of {state.get('target_url','unknown')}.\n\n"
                f"Target technologies: {[t.get('name') for t in state.get('technologies', [])]}\n\n"
                f"Findings to validate:\n{findings_text}"
            )
            try:
                resp = client.messages.create(
                    model=model,
                    max_tokens=min(400 + 400 * len(batch), 8192),
                    system=_VALIDATION_SYSTEM,
                    messages=[{"role": "user", "content": user_msg}],
                )
                text = "".join(b.text for b in resp.content if b.type == "text")
                parsed = json.loads(text)
                # Merge original finding data with validation output
                for orig, val in zip(batch, parsed):
                    merged = {**orig, **val}
                    if val.get("confirmed", True):
                        validated.append(merged)
            except Exception as e:
                errors.append(f"Validation batch {i//8}: {e}")
                # On error, include raw findings
                validated.extend(batch)

        return {**state, "validated_findings": validated, "errors": errors}

    except Exception as e:
        errors.append(f"Validation agent: {e}")
        return {**state, "validated_findings": raw_findings, "errors": errors}
