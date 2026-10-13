"""
FastAPI REST API Server for Ring Signature Monero Clsag.
"""
from typing import Dict, Any, List, Optional
import hmac
import os
from pathlib import Path
from fastapi import FastAPI, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .base import AuditLogger, PHIGuard, SecurityException
from .models import SystemTaskPayload, ConsensusDossier
from .supervisor import SystemSupervisor

supervisor = SystemSupervisor(model_provider="mock")

app = FastAPI(
    title="Ring Signature Monero Clsag API",
    description="Rule-based evaluation demonstration; not a CLSAG cryptographic implementation",
    version="3.0.0-ENTERPRISE",
)


class ChatRequest(BaseModel):
    query: str


@app.get("/health")
def health():
    return {"status": "HEALTHY", "service": "ring-signature-monero-clsag", "domain": "Threshold-rule demonstration", "standard": "Demonstration rules only", "version": "3.0.0-ENTERPRISE"}


@app.get("/metrics")
def metrics():
    return {
        "dossiers_processed_total": len(supervisor.dossier_registry),
        "audit_blocks_total": len(AuditLogger.get_trail()),
        "system_status": "RUNNING"
    }


@app.post("/api/audit")
def api_audit(payload: SystemTaskPayload):
    try:
        dossier = supervisor.process_task(payload)
    except SecurityException:
        raise HTTPException(status_code=422, detail="Sensitive identifiers are not permitted")
    return dossier.to_dict()


@app.post("/api/chat")
def api_chat(req: ChatRequest):
    try:
        ans = supervisor.query_supervisory_chat(req.query)
        return {"response": ans}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/audit/logs")
def api_audit_logs(x_audit_api_key: Optional[str] = Header(default=None)):
    """Audit metadata may identify requests; require explicit API access."""
    expected_key = os.getenv("AUDIT_LOGS_API_KEY")
    if not expected_key or not x_audit_api_key or not hmac.compare_digest(x_audit_api_key, expected_key):
        raise HTTPException(status_code=403, detail="Audit log access is disabled or unauthorized")
    return {"audit_trail": AuditLogger.get_trail(), "verified": AuditLogger.verify_integrity()}

# Serve the local console without changing the existing API routes.
# The static site also runs independently on GitHub Pages.
_web_directory = Path(__file__).resolve().parent.parent / "web"
if _web_directory.is_dir():
    app.mount("/", StaticFiles(directory=str(_web_directory), html=True), name="console")
