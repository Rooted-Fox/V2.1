"""OWASP ZAP DAST scanner — speed-tuned with progress callback."""
from __future__ import annotations

import time
from typing import Callable, List, Optional

import requests

from models import OwaspCategory, RawFinding
from runtime_settings import get_settings
from scanners.base import BaseScanner

_RISK_TO_SEV = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
_AJAX_MAX_SEC = 120   # reduced from 300 — faster SPA crawl

_ALERT_KEYWORDS = {
    OwaspCategory.A01_ACCESS_CONTROL: ["access control","path traversal","directory traversal","idor","privilege"],
    OwaspCategory.A02_MISCONFIGURATION: ["misconfiguration","default credential","server leaks","x-content-type","x-frame-options","content security policy","hsts","clickjacking","information disclosure","directory listing","debug"],
    OwaspCategory.A03_SUPPLY_CHAIN: ["vulnerable js library","retire.js","outdated library","sri","subresource integrity"],
    OwaspCategory.A04_CRYPTO_FAILURES: ["tls","ssl","certificate","weak cipher","plaintext","secure flag","mixed content","rc4","des","md5","sha1"],
    OwaspCategory.A05_INJECTION: ["sql injection","cross site scripting","xss","command injection","ldap injection","nosql injection","template injection","ssti","code injection"],
    OwaspCategory.A06_INSECURE_DESIGN: ["business logic","rate limit","brute force","account enumeration"],
    OwaspCategory.A07_AUTH_FAILURES: ["authentication","session fixation","session","jwt","credential","login","password"],
    OwaspCategory.A08_INTEGRITY_FAILURES: ["deserialization","integrity","unsigned","object injection"],
    OwaspCategory.A09_LOGGING_FAILURES: ["logging","monitoring","audit"],
    OwaspCategory.A10_EXCEPTIONAL: ["denial of service","dos","resource exhaustion","stack trace","exception","error handling","crash","redos","server side request forgery","ssrf"],
}


def _infer_category(alert_name: str) -> OwaspCategory:
    lowered = alert_name.lower()
    for category, keywords in _ALERT_KEYWORDS.items():
        if any(kw in lowered for kw in keywords):
            return category
    return OwaspCategory.A02_MISCONFIGURATION


class ZapScanner(BaseScanner):
    def __init__(self, target_url: str):
        self.target_url = target_url
        rt = get_settings()
        self.base = rt["zap_api_url"]
        self.params = {"apikey": rt["zap_api_key"]}

    def _get(self, path: str, timeout: int = 30, **extra):
        r = requests.get(f"{self.base}{path}", params={**self.params, **extra}, timeout=timeout)
        r.raise_for_status()
        return r.json()

    def _message_context(self, msg_id: Optional[str]) -> str:
        if not msg_id:
            return ""
        try:
            msg = self._get("/JSON/core/view/message/", id=msg_id, timeout=10).get("message", {})
        except requests.RequestException:
            return ""
        req = f"{msg.get('requestHeader','')}\n{msg.get('requestBody','')}"
        res = f"{msg.get('responseHeader','')}\n{msg.get('responseBody','')}"
        return f"--- request ---\n{req}\n--- response ---\n{res}"[:3000]

    def _maximize_thoroughness(self) -> None:
        for strength in ["HIGH"]:
            try:
                self._get("/JSON/ascan/action/setPolicyAttackStrength/",
                          scanPolicyName="Default Policy", attackStrength=strength)
                self._get("/JSON/ascan/action/setPolicyAlertThreshold/",
                          scanPolicyName="Default Policy", alertThreshold="LOW")
            except requests.RequestException:
                pass

    def _ajax_spider(self) -> None:
        try:
            self._get("/JSON/ajaxSpider/action/scan/", url=self.target_url)
        except requests.RequestException:
            return
        deadline = time.time() + _AJAX_MAX_SEC
        while True:
            try:
                status = self._get("/JSON/ajaxSpider/view/status/", timeout=10).get("status")
            except requests.RequestException:
                return
            if status != "running":
                return
            if time.time() > deadline:
                try:
                    self._get("/JSON/ajaxSpider/action/stop/")
                except requests.RequestException:
                    pass
                return
            time.sleep(2)

    def scan(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[RawFinding]:
        self._maximize_thoroughness()

        # Classic spider
        self._get("/JSON/spider/action/scan/", url=self.target_url, timeout=30)
        while int(self._get("/JSON/spider/view/status/", timeout=10)["status"]) < 100:
            time.sleep(2)

        # Ajax spider
        self._ajax_spider()

        if progress_callback:
            progress_callback("spider_done")

        # Active scan
        scan_id = self._get("/JSON/ascan/action/scan/", url=self.target_url, timeout=30)["scan"]
        while int(self._get("/JSON/ascan/view/status/", scanId=scan_id, timeout=10)["status"]) < 100:
            time.sleep(4)  # slightly faster polling

        if progress_callback:
            progress_callback("active_done")

        alerts = self._get("/JSON/core/view/alerts/", baseurl=self.target_url,
                           timeout=30).get("alerts", [])
        findings: List[RawFinding] = []
        for alert in alerts:
            evidence = (self._message_context(alert.get("messageId")) or
                        alert.get("evidence", ""))
            findings.append(RawFinding(
                tool="dast",
                category=_infer_category(alert.get("alert", "")),
                title=alert.get("alert", "security finding"),
                url=alert.get("url"),
                raw_severity=_RISK_TO_SEV.get(alert.get("risk"), "low"),
                description=alert.get("description", ""),
                evidence=evidence,
            ))
        return findings
