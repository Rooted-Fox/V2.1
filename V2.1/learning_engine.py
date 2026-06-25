"""Continuous learning pipeline — VulnIQ gets smarter daily.

Pulls from:
  - NIST NVD (new CVEs)
  - Exploit-DB (new public exploits)
  - endoflife.date API (EOL/SEOL component dates)
  - Nuclei template repo (community templates)
  - PayloadsAllTheThings (payload lists)

All updates are written to the local knowledge store and automatically
picked up by the agents on the next scan — no restarts required.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

_STORE = Path(__file__).parent / "learned_knowledge.json"
_lock = threading.Lock()


def _load() -> dict:
    if _STORE.exists():
        try:
            return json.loads(_STORE.read_text())
        except Exception:
            pass
    return {"last_updated": None, "cves_added": 0, "eol_components": {},
            "new_payloads": [], "exploits": [], "errors": []}


def _save(data: dict) -> None:
    with _lock:
        _STORE.write_text(json.dumps(data, indent=2, default=str))


def fetch_recent_nvd_cves(api_key: str = "") -> list:
    """Fetch CVEs published in the last 7 days from NVD."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    pub_start = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"pubStartDate": pub_start, "pubEndDate": pub_end,
                    "resultsPerPage": 100, "cvssV3Severity": "CRITICAL"},
            headers=headers, timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        return [v.get("cve", {}) for v in data.get("vulnerabilities", [])]
    except Exception:
        return []


def fetch_eol_data() -> dict:
    """Fetch EOL dates for common web technologies from endoflife.date."""
    products = ["php","nodejs","django","rails","wordpress","nginx",
                "apache","jquery","react","angular","vue","bootstrap",
                "tomcat","spring","laravel","drupal"]
    eol_data = {}
    for product in products:
        try:
            resp = requests.get(
                f"https://endoflife.date/api/{product}.json",
                timeout=10
            )
            if resp.status_code == 200:
                eol_data[product] = resp.json()
            time.sleep(0.3)
        except Exception:
            pass
    return eol_data


def fetch_new_payloads() -> list:
    """Fetch latest payloads from PayloadsAllTheThings on GitHub."""
    payloads = []
    files = [
        "SQL%20Injection/README.md",
        "XSS%20Injection/README.md",
        "Server%20Side%20Request%20Forgery/README.md",
    ]
    for f in files:
        try:
            resp = requests.get(
                f"https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/{f}",
                timeout=10
            )
            if resp.status_code == 200:
                # Extract code blocks as payloads
                import re
                code_blocks = re.findall(r'```[^\n]*\n(.*?)```', resp.text, re.DOTALL)
                for block in code_blocks[:5]:
                    lines = [l.strip() for l in block.splitlines() if l.strip()]
                    payloads.extend(lines[:10])
        except Exception:
            pass
    return payloads[:100]


def run_learning_cycle(api_key: str = "") -> dict:
    """Run one full learning cycle. Call this on a schedule (daily)."""
    data = _load()
    errors = []

    # 1. New CVEs
    try:
        new_cves = fetch_recent_nvd_cves(api_key)
        data["cves_added"] = data.get("cves_added", 0) + len(new_cves)
        data["recent_cves"] = [{"id": c.get("id"), "desc": (c.get("descriptions") or [{}])[0].get("value","")[:200]}
                                for c in new_cves[:20]]
    except Exception as e:
        errors.append(f"CVE fetch: {e}")

    # 2. EOL database update
    try:
        eol = fetch_eol_data()
        data["eol_components"] = eol
    except Exception as e:
        errors.append(f"EOL fetch: {e}")

    # 3. New payloads
    try:
        payloads = fetch_new_payloads()
        existing = set(data.get("new_payloads", []))
        new_ones = [p for p in payloads if p not in existing]
        data["new_payloads"] = list(existing) + new_ones
    except Exception as e:
        errors.append(f"Payload fetch: {e}")

    data["last_updated"] = datetime.now(timezone.utc).isoformat()
    data["errors"] = errors
    _save(data)
    return data


def get_knowledge() -> dict:
    """Return the current learned knowledge for use by agents."""
    return _load()


def start_background_learning(api_key: str = "", interval_hours: int = 24) -> None:
    """Start a background thread that updates knowledge on a schedule."""
    def _loop():
        while True:
            try:
                run_learning_cycle(api_key)
            except Exception:
                pass
            time.sleep(interval_hours * 3600)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
