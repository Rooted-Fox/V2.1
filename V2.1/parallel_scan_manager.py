"""Parallel scan manager — each target gets its own independent scan job.

Unlike the old single-scan model, this allows N scans to run simultaneously,
each with its own progress, status, findings, and lifecycle. ZAP handles
one target at a time internally so each job gets its own ZAP session context.
"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from orchestrator import Orchestrator

_jobs: Dict[str, dict] = {}
_lock = threading.Lock()


def _new_job(job_id: str, target_url: str, app_name: str) -> dict:
    return {
        "job_id": job_id,
        "target_url": target_url,
        "app_name": app_name,
        "status": "queued",      # queued | running | complete | failed
        "progress": 0,
        "status_message": "Queued",
        "started_at": None,
        "finished_at": None,
        "last_error": None,
        "raw_count": 0,
        "scanner_log": [],
    }


def start_scan(target_url: str, app_name: Optional[str] = None) -> str:
    """Start an independent scan for one target. Returns the job_id."""
    job_id = str(uuid.uuid4())[:8]
    resolved_name = app_name or _hostname(target_url)
    job = _new_job(job_id, target_url, resolved_name)

    with _lock:
        _jobs[job_id] = job

    def _run() -> None:
        with _lock:
            _jobs[job_id]["status"] = "running"
            _jobs[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()

        try:
            orch = Orchestrator(target_urls=[target_url], app_names=[resolved_name])

            # Wire live progress into the job dict
            def _progress_hook():
                with _lock:
                    _jobs[job_id]["progress"] = orch.progress
                    _jobs[job_id]["status_message"] = orch.status_message

            # Patch orchestrator to call hook on each advance
            original_advance = orch._advance
            def _hooked_advance(stage, message):
                original_advance(stage, message)
                _progress_hook()
            orch._advance = _hooked_advance

            findings = orch.scan()
            with _lock:
                _jobs[job_id]["status"] = "complete"
                _jobs[job_id]["progress"] = 100
                _jobs[job_id]["status_message"] = "Complete"
                _jobs[job_id]["raw_count"] = len(findings)
                _jobs[job_id]["scanner_log"] = orch.scanner_log
        except Exception as exc:
            with _lock:
                _jobs[job_id]["status"] = "failed"
                _jobs[job_id]["last_error"] = str(exc)
                _jobs[job_id]["status_message"] = "Failed"
        finally:
            with _lock:
                _jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

    threading.Thread(target=_run, daemon=True).start()
    return job_id


def get_job(job_id: str) -> Optional[dict]:
    with _lock:
        return dict(_jobs.get(job_id, {}))


def all_jobs() -> List[dict]:
    with _lock:
        return [dict(j) for j in _jobs.values()]


def active_jobs() -> List[dict]:
    with _lock:
        return [dict(j) for j in _jobs.values() if j["status"] in ("queued", "running")]


def _hostname(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url
