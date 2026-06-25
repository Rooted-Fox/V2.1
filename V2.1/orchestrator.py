"""Multi-tool black-box scan pipeline with real-time progress reporting.

Scan stages and their progress weights (must sum to 100):
  ZAP spider        10%
  ZAP active scan   35%
  SQLMap            10%
  Nuclei            10%
  Nikto              8%
  SSL scanner        5%
  FFuf               7%
  Exposed paths      3%
  NVD historic      12%
"""
from __future__ import annotations

import concurrent.futures
import threading
from typing import Callable, List, Optional
from urllib.parse import urlparse

from models import RawFinding
from pending_store import PendingFindingsStore
from runtime_settings import get_settings
from scanners.base import ScannerNotInstalled
from scanners.exposed_paths import check_exposed_paths
from scanners.ffuf_scanner import run_ffuf
from scanners.nikto_scanner import run_nikto
from scanners.nuclei_scanner import run_nuclei
from scanners.nvd_scanner import run_nvd_scan
from scanners.sqlmap_scanner import run_sqlmap
from scanners.ssl_scanner import run_ssl_scan
from scanners.zap_scanner import ZapScanner

# Progress weights per stage (must sum to 100)
_WEIGHTS = {
    "zap_spider":     10,
    "zap_active":     35,
    "sqlmap":         10,
    "nuclei":         10,
    "nikto":           8,
    "ssl":             5,
    "ffuf":            7,
    "exposed":         3,
    "nvd":            12,
}


def _default_app_name(url: str) -> str:
    return urlparse(url).hostname or url


class Orchestrator:
    def __init__(self, target_urls: List[str], app_names: Optional[List[str]] = None):
        # Support multiple targets
        self.target_urls = target_urls if isinstance(target_urls, list) else [target_urls]
        self.app_names = app_names or []
        self.pending_store = PendingFindingsStore()
        self.scanner_log: List[str] = []
        self._progress = 0
        self._progress_lock = threading.Lock()
        self._status_message = "Initialising..."

    @property
    def progress(self) -> int:
        with self._progress_lock:
            return self._progress

    @property
    def status_message(self) -> str:
        with self._progress_lock:
            return self._status_message

    def _advance(self, stage: str, message: str) -> None:
        weight = _WEIGHTS.get(stage, 0)
        with self._progress_lock:
            self._progress = min(100, self._progress + weight)
            self._status_message = message

    def _safe_run(self, fn: Callable, *args, stage: str, label: str) -> List[RawFinding]:
        try:
            results = fn(*args)
            return results
        except ScannerNotInstalled as exc:
            self.scanner_log.append(f"[skip] {label}: {exc}")
            return []
        except Exception as exc:
            self.scanner_log.append(f"[error] {label}: {exc}")
            return []

    def _scan_one(self, target_url: str, app_name: str) -> List[RawFinding]:
        all_findings: List[RawFinding] = []

        # Phase 1: ZAP (runs solo — owns its daemon session)
        self._advance("zap_spider", "Crawling application structure...")
        zap = ZapScanner(target_url)
        try:
            zap_findings = zap.scan(progress_callback=self._zap_progress_cb)
            all_findings.extend(zap_findings)
        except ScannerNotInstalled as exc:
            self.scanner_log.append(f"[skip] zap: {exc}")
        except Exception as exc:
            self.scanner_log.append(f"[error] zap: {exc}")

        # Phase 2: parallel scanners
        parallel = [
            ("sqlmap",  run_sqlmap,           target_url, "sqlmap",  "Testing SQL injection paths..."),
            ("nuclei",  run_nuclei,           target_url, "nuclei",  "Running CVE template checks..."),
            ("nikto",   run_nikto,            target_url, "nikto",   "Analysing server configuration..."),
            ("ssl",     run_ssl_scan,         target_url, "ssl",     "Checking TLS/cryptographic posture..."),
            ("ffuf",    run_ffuf,             target_url, "ffuf",    "Discovering hidden endpoints..."),
            ("exposed", check_exposed_paths,  target_url, "exposed", "Checking for exposed sensitive files..."),
            ("nvd",     run_nvd_scan,         target_url, "nvd",     "Looking up historic CVEs..."),
        ]

        def run_parallel(item):
            stage, fn, url, label, msg = item
            results = self._safe_run(fn, url, stage=stage, label=label)
            self._advance(stage, msg)
            return results

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            for batch in concurrent.futures.as_completed(
                {executor.submit(run_parallel, item): item for item in parallel}
            ):
                try:
                    all_findings.extend(batch.result())
                except Exception:
                    pass

        # Filter and tag
        if get_settings()["skip_info_findings"]:
            all_findings = [f for f in all_findings
                            if (f.raw_severity or "").lower() != "info"]
        for f in all_findings:
            f.app_name = app_name
            f.url = f.url or target_url

        return all_findings

    def _zap_progress_cb(self, stage: str) -> None:
        """ZAP scanner calls this to report internal progress."""
        if stage == "spider_done":
            self._advance("zap_spider", "Application crawl complete, active scanning...")
        elif stage == "active_done":
            self._advance("zap_active", "Active vulnerability scan complete...")

    def scan(self) -> List[RawFinding]:
        all_findings: List[RawFinding] = []
        for i, url in enumerate(self.target_urls):
            app_name = (self.app_names[i] if i < len(self.app_names) else None) or _default_app_name(url)
            with self._progress_lock:
                self._progress = 0
                self._status_message = f"Starting scan of {app_name}..."
            findings = self._scan_one(url, app_name)
            all_findings.extend(findings)
            self.pending_store.save_many(findings)

        with self._progress_lock:
            self._progress = 100
            self._status_message = "Scan complete"
        return all_findings
