"""Recon Agent — maps the full attack surface before any exploitation.

Tools used (graceful degradation if not installed):
  - httpx: fast HTTP probing and tech fingerprinting
  - katana: modern web crawler (JS-aware)
  - subfinder: passive subdomain discovery
  - arjun: hidden parameter discovery
  - playwright: browser-based crawling for SPAs
  - built-in tech_fingerprint module
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests

from agents_graph.state import AgentState
from scanners.tech_fingerprint import fingerprint


def _run(cmd: List[str], timeout: int = 120) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def _katana_crawl(url: str) -> List[str]:
    if not shutil.which("katana"):
        # Fallback: basic link extraction with requests
        try:
            import re
            resp = requests.get(url, timeout=10,
                                headers={"User-Agent":"Mozilla/5.0"},
                                allow_redirects=True)
            links = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
            return [l for l in links if l.startswith("http")][:100]
        except Exception:
            return []
    out = _run(["katana", "-u", url, "-jc", "-silent", "-o", "/dev/stdout",
                "-depth", "3", "-timeout", "10"], timeout=120)
    return [l.strip() for l in out.splitlines() if l.strip().startswith("http")]


def _subfinder_scan(domain: str) -> List[str]:
    if not shutil.which("subfinder"):
        return []
    out = _run(["subfinder", "-d", domain, "-silent"], timeout=60)
    return [l.strip() for l in out.splitlines() if l.strip()]


def _httpx_probe(urls: List[str]) -> List[Dict[str, Any]]:
    if not shutil.which("httpx") or not urls:
        return []
    tmp = tempfile.mktemp()
    with open(tmp, "w") as f:
        f.write("\n".join(urls))
    out = _run(["httpx", "-l", tmp, "-json", "-silent",
                "-title", "-tech-detect", "-status-code"], timeout=60)
    results = []
    for line in out.splitlines():
        try:
            results.append(json.loads(line))
        except Exception:
            pass
    return results


def _arjun_discover(url: str) -> List[str]:
    if not shutil.which("arjun"):
        return []
    out = _run(["arjun", "-u", url, "--stable", "-oJ", "/dev/stdout",
                "--silent"], timeout=90)
    try:
        data = json.loads(out)
        return data.get(url, {}).get("params", [])
    except Exception:
        return []


def _discover_forms(url: str) -> List[Dict[str, Any]]:
    """Extract all forms from a page."""
    try:
        import re
        resp = requests.get(url, timeout=10,
                            headers={"User-Agent":"Mozilla/5.0"},
                            allow_redirects=True)
        forms = []
        form_blocks = re.findall(r'<form[^>]*>.*?</form>', resp.text,
                                 re.DOTALL | re.IGNORECASE)
        for block in form_blocks:
            action_m = re.search(r'action=["\']([^"\']+)', block, re.I)
            method_m = re.search(r'method=["\']([^"\']+)', block, re.I)
            fields = re.findall(r'name=["\']([^"\']+)', block, re.I)
            forms.append({
                "url": url,
                "action": action_m.group(1) if action_m else "",
                "method": (method_m.group(1) if method_m else "GET").upper(),
                "fields": fields,
            })
        return forms
    except Exception:
        return []


def run_recon(state: AgentState) -> AgentState:
    """Main recon function — called by LangGraph as a node."""
    url = state.get("target_url", "")
    if not url:
        return {**state, "errors": state.get("errors", []) + ["Recon: no target URL"]}

    state = {**state, "current_agent": "recon", "iteration": state.get("iteration", 0) + 1}
    errors = list(state.get("errors", []))

    # 1. Technology fingerprinting
    try:
        techs_raw = fingerprint(url)
        technologies = [{"name": t, "version": v} for t, v in techs_raw
                        if t not in ("generator", "powered_by", "framework", "CMS-detected")]
    except Exception as e:
        technologies = []
        errors.append(f"Recon fingerprint: {e}")

    # 2. Subdomain discovery
    domain = urlparse(url).hostname or ""
    subdomains = []
    try:
        subdomains = _subfinder_scan(domain)
    except Exception as e:
        errors.append(f"Recon subfinder: {e}")

    # 3. Deep crawling with Katana
    endpoints = []
    try:
        endpoints = _katana_crawl(url)
    except Exception as e:
        errors.append(f"Recon katana: {e}")

    # 4. HTTP probing of discovered endpoints
    js_files = [e for e in endpoints if e.endswith(".js")]
    try:
        _httpx_probe(endpoints[:50])  # probe top 50
    except Exception as e:
        errors.append(f"Recon httpx: {e}")

    # 5. Form discovery
    forms = []
    try:
        forms = _discover_forms(url)
        for ep in endpoints[:10]:
            forms.extend(_discover_forms(ep))
    except Exception as e:
        errors.append(f"Recon forms: {e}")

    # 6. Hidden parameter discovery on top endpoints
    hidden_params = {}
    try:
        for ep in [url] + endpoints[:5]:
            params = _arjun_discover(ep)
            if params:
                hidden_params[ep] = params
    except Exception as e:
        errors.append(f"Recon arjun: {e}")

    return {
        **state,
        "technologies": technologies,
        "subdomains": subdomains,
        "endpoints": list(set(endpoints)),
        "js_files": js_files,
        "forms": forms,
        "hidden_params": hidden_params,
        "errors": errors,
    }
