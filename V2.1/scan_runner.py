"""Background scan runner with real-time progress reporting."""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import List, Optional

from orchestrator import Orchestrator

_state = {
    "running": False,
    "targets": [],
    "app_names": [],
    "started_at": None,
    "finished_at": None,
    "last_error": None,
    "last_raw_count": None,
    "scanner_log": [],
    "progress": 0,
    "status_message": "idle",
}
_lock = threading.Lock()
_orchestrator_ref: Optional[Orchestrator] = None


def status() -> dict:
    with _lock:
        s = dict(_state)
    # pull live progress from orchestrator if running
    if _orchestrator_ref and s["running"]:
        s["progress"] = _orchestrator_ref.progress
        s["status_message"] = _orchestrator_ref.status_message
    return s


def start_scan(target_urls: List[str], app_names: Optional[List[str]] = None) -> bool:
    global _orchestrator_ref
    if isinstance(target_urls, str):
        target_urls = [target_urls]
    with _lock:
        if _state["running"]:
            return False
        _state.update(
            running=True,
            targets=target_urls,
            app_names=app_names or [],
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
            last_error=None,
            scanner_log=[],
            progress=0,
            status_message="Starting...",
        )

    def _run() -> None:
        global _orchestrator_ref
        try:
            orch = Orchestrator(target_urls=target_urls, app_names=app_names)
            _orchestrator_ref = orch
            findings = orch.scan()
            with _lock:
                _state["last_raw_count"] = len(findings)
                _state["scanner_log"] = orch.scanner_log
                _state["progress"] = 100
                _state["status_message"] = "Complete"
        except Exception as exc:
            with _lock:
                _state["last_error"] = str(exc)
                _state["status_message"] = "Failed"
        finally:
            _orchestrator_ref = None
            with _lock:
                _state["running"] = False
                _state["finished_at"] = datetime.now(timezone.utc).isoformat()

    threading.Thread(target=_run, daemon=True).start()
    return True
