"""VulnIQ FastAPI backend."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import report_generator
import runtime_settings
import scan_runner
import scheduler
import triage_job
from models import RemediationStatus
from pending_store import PendingFindingsStore
from store import FindingsStore
from token_store import TokenStore

app = FastAPI(title="VulnIQ API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET","POST","PATCH","DELETE"])

store = FindingsStore()
pending_store = PendingFindingsStore()
token_store = TokenStore()
api = APIRouter(prefix="/api")


# ── apps ──────────────────────────────────────────────────
@api.get("/apps")
def list_apps():
    return store.list_apps()


# ── findings (validated) ──────────────────────────────────
@api.get("/findings")
def list_findings(app_name: Optional[str] = None):
    return [dict(r) for r in store.all(app_name=app_name)]


@api.get("/findings/{finding_id}")
def get_finding(finding_id: int):
    row = store.get(finding_id)
    if not row:
        raise HTTPException(404, "Finding not found")
    return dict(row)


class RemediationUpdate(BaseModel):
    status: RemediationStatus
    notes: Optional[str] = None


@api.patch("/findings/{finding_id}/remediation")
def update_remediation(finding_id: int, body: RemediationUpdate):
    store.update_remediation(finding_id, body.status, body.notes)
    return {"id": finding_id, "status": body.status.value}


@api.patch("/findings/{finding_id}")
def update_finding_status(finding_id: int, body: RemediationUpdate):
    return update_remediation(finding_id, body)


# ── summaries ─────────────────────────────────────────────
@api.get("/summary/severity")
def severity_summary(app_name: Optional[str] = None):
    return store.severity_summary(app_name=app_name)


@api.get("/summary/category")
def category_summary(app_name: Optional[str] = None):
    return store.category_summary(app_name=app_name)


@api.get("/summary/remediation")
def remediation_summary(app_name: Optional[str] = None):
    return store.remediation_summary(app_name=app_name)


# ── attack chains ─────────────────────────────────────────
@api.get("/chains")
def list_chains(app_name: Optional[str] = None):
    import json
    result = []
    for r in store.chains(app_name=app_name):
        d = dict(r)
        try:
            d["finding_ids"] = json.loads(d.get("finding_ids", "[]"))
        except Exception:
            d["finding_ids"] = []
        result.append(d)
    return result


# ── comparison ────────────────────────────────────────────
@api.get("/comparison")
def scan_comparison(app_name: str, since: str):
    return store.scan_comparison(app_name, since)


# ── settings ──────────────────────────────────────────────
class SettingsUpdate(BaseModel):
    provider: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    agent_model: Optional[str] = None
    azure_foundry_endpoint: Optional[str] = None
    azure_foundry_api_key: Optional[str] = None
    zap_api_url: Optional[str] = None
    zap_api_key: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    nvd_api_key: Optional[str] = None
    token_limit: Optional[int] = None
    ai_enabled: Optional[bool] = None
    skip_info_findings: Optional[bool] = None


def _settings_view() -> dict:
    s = runtime_settings.get_settings()
    return {
        "provider": s["provider"],
        "anthropic_api_key_set": bool(s["anthropic_api_key"]),
        "anthropic_api_key_masked": runtime_settings.masked(s["anthropic_api_key"]),
        "agent_model": s["agent_model"],
        "azure_foundry_endpoint": s["azure_foundry_endpoint"],
        "azure_foundry_api_key_set": bool(s["azure_foundry_api_key"]),
        "azure_foundry_api_key_masked": runtime_settings.masked(s["azure_foundry_api_key"]),
        "zap_api_url": s["zap_api_url"],
        "zap_api_key_set": bool(s["zap_api_key"]),
        "slack_webhook_url_set": bool(s["slack_webhook_url"]),
        "nvd_api_key_set": bool(s["nvd_api_key"]),
        "token_limit": s["token_limit"],
        "ai_enabled": s["ai_enabled"],
        "skip_info_findings": s["skip_info_findings"],
    }


@api.get("/settings")
def get_settings():
    return _settings_view()


@api.post("/settings")
def update_settings(body: SettingsUpdate):
    runtime_settings.update_settings(**body.model_dump(exclude_none=True))
    return _settings_view()


# ── scan (multi-target) ───────────────────────────────────
class ScanRequest(BaseModel):
    targets: List[str]                    # list of URLs
    app_names: Optional[List[str]] = None # optional names per URL


@api.post("/scan")
def trigger_scan(body: ScanRequest):
    for url in body.targets:
        if not url.startswith(("http://", "https://")):
            raise HTTPException(400, f"Invalid URL (must start with http:// or https://): {url}")
    started = scan_runner.start_scan(body.targets, app_names=body.app_names)
    if not started:
        raise HTTPException(409, "A scan is already running.")
    return {"status": "started", "targets": body.targets}


@api.get("/scan/status")
def scan_status():
    return scan_runner.status()


# ── pending (enumerated findings — live) ──────────────────
@api.get("/pending")
def pending_summary(app_name: Optional[str] = None):
    rows = pending_store.pending(app_name=app_name)
    return {
        "count": len(rows),
        "by_category": pending_store.pending_summary(app_name=app_name),
        "findings": [dict(r) for r in rows],
    }


# ── triage ────────────────────────────────────────────────
class TriageRequest(BaseModel):
    app_name: Optional[str] = None


@api.post("/triage")
def trigger_triage(body: TriageRequest):
    if not runtime_settings.get_settings()["ai_enabled"]:
        raise HTTPException(400, "AI integration is off. Enable it in Settings.")
    if not runtime_settings.has_api_key():
        raise HTTPException(400, "Add your API credentials in Settings before approving triage.")
    pending_count = len(pending_store.pending(app_name=body.app_name))
    if pending_count == 0:
        raise HTTPException(400, "Nothing pending - run a scan first.")
    token_limit = runtime_settings.get_settings()["token_limit"]
    if not token_store.has_budget(token_limit):
        raise HTTPException(400, f"Token budget ({token_limit}) reached.")
    started = triage_job.start_triage(app_name=body.app_name, token_limit=token_limit)
    if not started:
        raise HTTPException(409, "Triage is already running.")
    return {"status": "started", "pending_count": pending_count}


@api.get("/triage/status")
def triage_status():
    return triage_job.status()


# ── tokens ────────────────────────────────────────────────
@api.get("/tokens")
def token_usage():
    s = runtime_settings.get_settings()
    used = token_store.total_used()
    limit = s["token_limit"]
    return {
        "used": used,
        "limit": limit,
        "remaining": max(limit - used, 0) if limit else None,
        "by_category": token_store.usage_by_category(),
    }


@api.post("/tokens/reset")
def reset_tokens():
    token_store.reset()
    return token_usage()


# ── reports ───────────────────────────────────────────────
@api.get("/report/html")
def html_report(app_name: Optional[str] = None, dashboard: str = "technical"):
    html = report_generator.generate_html(app_name=app_name, dashboard=dashboard)
    return Response(content=html, media_type="text/html")


@api.get("/report/csv")
def csv_report(app_name: Optional[str] = None):
    return Response(
        content=report_generator.generate_csv(app_name=app_name),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulniq-findings.csv"},
    )


@api.get("/report/json")
def json_report(app_name: Optional[str] = None):
    return Response(
        content=report_generator.generate_json(app_name=app_name),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=vulniq-findings.json"},
    )


# ── schedules ─────────────────────────────────────────────
class ScheduleCreate(BaseModel):
    target_url: str
    app_name: Optional[str] = None
    cron: str = "0 2 * * *"
    enabled: bool = True


@api.get("/schedules")
def list_schedules():
    return scheduler.list_schedules()


@api.post("/schedules")
def create_schedule(body: ScheduleCreate):
    return scheduler.add_schedule(body.target_url, body.app_name, body.cron, body.enabled)


@api.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: str):
    if not scheduler.delete_schedule(schedule_id):
        raise HTTPException(404, "Schedule not found")
    return {"deleted": schedule_id}


app.include_router(api)
_fe = Path(__file__).parent / "frontend"
app.mount("/", StaticFiles(directory=str(_fe), html=True), name="frontend")


# ── parallel scan manager endpoints ──────────────────────
import parallel_scan_manager
import url_checker

class SingleScanRequest(BaseModel):
    target_url: str
    app_name: Optional[str] = None

@api.post("/scan/single")
def start_single_scan(body: SingleScanRequest):
    """Start an independent scan for a single target — non-blocking."""
    if not body.target_url.startswith(("http://","https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    job_id = parallel_scan_manager.start_scan(body.target_url, body.app_name)
    return {"job_id": job_id, "status": "started", "target_url": body.target_url}

@api.get("/scan/jobs")
def list_scan_jobs():
    """Return all scan jobs (running + completed)."""
    return parallel_scan_manager.all_jobs()

@api.get("/scan/jobs/{job_id}")
def get_scan_job(job_id: str):
    job = parallel_scan_manager.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job

@api.post("/url/check")
def check_url_reachability(body: SingleScanRequest):
    """Check if a URL is reachable (with redirect following)."""
    return url_checker.check_url(body.target_url)

# ── learning engine endpoints ─────────────────────────────
import learning_engine

@api.get("/learning/status")
def learning_status():
    return learning_engine.get_knowledge()

@api.post("/learning/update")
def trigger_learning():
    from runtime_settings import get_settings
    api_key = get_settings().get("nvd_api_key","")
    data = learning_engine.run_learning_cycle(api_key)
    return {"status": "updated", "last_updated": data.get("last_updated"),
            "cves_added": data.get("cves_added", 0)}
