"""
Celery async task workers.
Scan jobs are queued here and dispatched to the scanner service via HTTP.
"""
import httpx
from datetime import datetime, timezone
from celery import Celery

from config import settings
from database import SessionLocal
from models import Agent, ScanResult, ScanStatus, AlertConfig
from alerting import send_alert_sync

celery_app = Celery(
    "watchtower",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    task_track_started=True,
)


def trigger_scan_task(agent_id: str, triggered_by: str = "manual"):
    """Enqueues a scan job — called from FastAPI background tasks."""
    run_scan.delay(agent_id, triggered_by)


@celery_app.task(bind=True, max_retries=2)
def run_scan(self, agent_id: str, triggered_by: str = "manual"):
    """
    Full red-team scan pipeline:
    1. Create RUNNING scan record
    2. POST to scanner service
    3. Score results + decide gate pass/fail
    4. Approve or block the agent
    5. Alert owner on failure
    """
    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            return

        scan = ScanResult(
            agent_id=agent_id,
            status=ScanStatus.RUNNING,
            triggered_by=triggered_by,
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        payload = {
            "scan_id": str(scan.id),
            "agent_id": str(agent.id),
            "endpoint_url": agent.endpoint_url,
            # Vendor-agnostic provider identity
            "provider": agent.provider,
            "provider_config": agent.provider_config or {},
            # Legacy Bedrock fields kept for backward compat with buildPromptfooConfig
            "bedrock_model_id": agent.bedrock_model_id,
            "bedrock_guardrail_id": agent.bedrock_guardrail_id,
            "mcp_servers": agent.mcp_servers or [],
            "allowed_tools": agent.allowed_tools or [],
            "mock_scan": settings.MOCK_SCAN,
        }

        try:
            with httpx.Client(timeout=600.0) as client:
                resp = client.post(f"{settings.SCANNER_SERVICE_URL}/scan", json=payload)
                resp.raise_for_status()
                results = resp.json()
        except Exception as exc:
            scan.status = ScanStatus.ERROR
            scan.summary = f"Scanner unreachable: {exc}"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            raise self.retry(exc=exc, countdown=30)

        scores = results.get("scores", {})
        scan.prompt_injection_score        = scores.get("prompt_injection", 0.0)
        scan.pii_leak_score                = scores.get("pii_leak", 0.0)
        scan.jailbreak_score               = scores.get("jailbreak", 0.0)
        scan.content_violation_score       = scores.get("content_violation", 0.0)
        scan.mcp_poisoning_score           = scores.get("mcp_poisoning", 0.0)
        scan.system_prompt_leakage_score   = scores.get("system_prompt_leakage", 0.0)
        scan.excessive_agency_score        = scores.get("excessive_agency", 0.0)
        scan.insecure_output_score         = scores.get("insecure_output", 0.0)
        scan.misinformation_score          = scores.get("misinformation", 0.0)
        scan.owasp_failures        = results.get("owasp_failures", [])
        scan.raw_report            = results.get("raw_report", {})
        scan.remediation_hints     = results.get("remediation_hints", [])
        scan.summary               = results.get("summary", "")
        scan.findings              = results.get("findings", [])
        scan.guardrail_config      = results.get("guardrail_config")

        # Updated formula — weighted across 9 categories (weights sum to 1.0)
        scan.overall_risk_score = round(
            (scan.prompt_injection_score        or 0) * 0.23
            + (scan.jailbreak_score             or 0) * 0.18
            + (scan.pii_leak_score              or 0) * 0.15
            + (scan.system_prompt_leakage_score or 0) * 0.14
            + (scan.excessive_agency_score      or 0) * 0.10
            + (scan.mcp_poisoning_score         or 0) * 0.10
            + (scan.misinformation_score        or 0) * 0.07
            + (scan.insecure_output_score       or 0) * 0.02
            + (scan.content_violation_score     or 0) * 0.01
        , 2)

        gate_passed = (
            (scan.prompt_injection_score        or 0) <= settings.PROMPT_INJECTION_THRESHOLD
            and (scan.jailbreak_score           or 0) <= settings.JAILBREAK_THRESHOLD
            and (scan.pii_leak_score            or 0) <= settings.PII_LEAK_THRESHOLD
            and (scan.content_violation_score   or 0) <= settings.CONTENT_VIOLATION_THRESHOLD
            and (scan.system_prompt_leakage_score or 0) <= settings.SYSTEM_PROMPT_LEAKAGE_THRESHOLD
            and (scan.excessive_agency_score    or 0) <= settings.EXCESSIVE_AGENCY_THRESHOLD
            and (scan.insecure_output_score     or 0) <= settings.INSECURE_OUTPUT_THRESHOLD
            and (scan.mcp_poisoning_score       or 0) <= settings.MCP_POISONING_THRESHOLD
            and (scan.misinformation_score      or 0) <= settings.MISINFORMATION_THRESHOLD
        )
        scan.gate_passed = gate_passed
        scan.status = ScanStatus.PASSED if gate_passed else ScanStatus.FAILED
        scan.completed_at = datetime.now(timezone.utc)
        agent.is_approved = gate_passed
        db.commit()

        if not gate_passed:
            cfg = db.query(AlertConfig).filter(AlertConfig.agent_id == agent_id).first()
            if cfg and cfg.alert_on_scan_fail:
                failed = [k for k, v in scores.items() if v and v > 0]
                send_alert_sync(
                    agent=agent, alert_cfg=cfg,
                    message=(
                        f"🚨 Gate FAILED for *{agent.name}* ({agent.team_name})\n"
                        f"Failed: {', '.join(failed)} | "
                        f"OWASP: {', '.join(scan.owasp_failures or [])} | "
                        f"Risk: {scan.overall_risk_score:.1f}%\n"
                        f"Agent is *blocked from production*."
                    ),
                )

        return {"scan_id": str(scan.id), "gate_passed": gate_passed,
                "risk_score": scan.overall_risk_score}
    finally:
        db.close()
