from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Optional
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, ConfigDict
from uuid import UUID

from database import get_db, init_db
from models import Agent, ScanResult, GuardrailEvent, AlertConfig, ScanStatus, SeverityLevel
from tasks import trigger_scan_task
from alerting import send_alert
from config import settings, get_scan_mode, set_scan_mode
from galactus import galactus as galactus_engine
from auth import (
    auth_middleware, auth_status, create_token, verify_password,
    set_auth_cookie, clear_auth_cookie,
    list_users, create_user, update_password, delete_user,
)

app = FastAPI(
    title="AI Watchtower",
    description="Pre-deployment red teaming gate + cross-team security aggregation",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# ── Auth middleware — runs before every request ───────────────────────────────
app.middleware("http")(auth_middleware)

# Serve the web UI
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.on_event("startup")
def on_startup():
    init_db()


# ─────────────────────────────────────────
# Auth endpoints  (all public — no token required)
# ─────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/login", include_in_schema=False)
def login_page():
    return FileResponse("static/login.html")


@app.post("/auth/login", include_in_schema=False)
def do_login(req: LoginRequest, response: Response, db: Session = Depends(get_db)):
    if not verify_password(req.username, req.password, db):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password")
    token = create_token(req.username)
    set_auth_cookie(response, token)
    return {"status": "ok", "username": req.username}


@app.post("/auth/logout", include_in_schema=False)
def do_logout(response: Response):
    clear_auth_cookie(response)
    return {"status": "ok"}


@app.get("/auth/status", include_in_schema=False)
def get_auth_status():
    """Returns auth mode metadata consumed by the login page."""
    return auth_status()


# ─────────────────────────────────────────
# UI entry point
# ─────────────────────────────────────────

@app.get("/", include_in_schema=False)
def ui():
    return FileResponse("static/index.html")


@app.get("/settings", include_in_schema=False)
def settings_page():
    return FileResponse("static/settings.html")


# ─────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────

class MCPServer(BaseModel):
    name: str
    url: str
    description: Optional[str] = None


class AgentRegisterRequest(BaseModel):
    name: str
    team_name: str
    owner_email: str
    slack_channel: Optional[str] = None
    endpoint_url: str
    # Legacy Bedrock fields — still accepted, mapped to provider_config for bedrock provider
    bedrock_model_id: Optional[str] = None
    framework: Optional[str] = None
    mcp_servers: List[MCPServer] = []
    allowed_tools: List[str] = []
    bedrock_guardrail_id: Optional[str] = None
    bedrock_guardrail_version: Optional[str] = None
    # Vendor-agnostic provider fields
    provider: Optional[str] = None           # openai | anthropic | ollama | openai_compatible | bedrock | custom
    provider_config: Optional[dict] = None   # provider-specific config (see models.py for shape)
    # NeMo Guardrails runtime protection (optional, provider-agnostic)
    nemo_guardrails_config: Optional[dict] = None


class AgentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    team_name: str
    owner_email: str
    endpoint_url: str
    bedrock_model_id: Optional[str] = None
    framework: Optional[str] = None
    is_approved: bool
    provider: Optional[str] = None
    provider_config: Optional[dict] = None
    nemo_guardrails_config: Optional[dict] = None
    created_at: datetime


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: UUID
    status: str
    triggered_by: str
    # Core 5 scores (backward-compatible)
    prompt_injection_score: Optional[float] = None
    pii_leak_score: Optional[float] = None
    jailbreak_score: Optional[float] = None
    content_violation_score: Optional[float] = None
    mcp_poisoning_score: Optional[float] = None
    overall_risk_score: Optional[float] = None
    # Expanded OWASP category scores
    system_prompt_leakage_score: Optional[float] = None
    excessive_agency_score: Optional[float] = None
    insecure_output_score: Optional[float] = None
    misinformation_score: Optional[float] = None
    owasp_failures: Optional[list] = None
    remediation_hints: Optional[list] = None
    summary: Optional[str] = None
    gate_passed: Optional[bool] = None
    # Rich per-probe findings (raw_report is intentionally not exposed)
    findings: Optional[list] = None
    # Provider-specific guardrail recommendations
    guardrail_config: Optional[dict] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime


class GuardrailEventIngest(BaseModel):
    agent_id: str
    event_type: str
    severity: str
    source: str
    details: Optional[dict] = None
    blocked: bool = True
    session_id: Optional[str] = None
    input_hash: Optional[str] = None


class GuardrailEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: UUID
    event_type: str
    severity: str
    source: str
    blocked: bool
    session_id: Optional[str] = None
    details: Optional[dict] = None
    occurred_at: datetime


class DashboardMetrics(BaseModel):
    total_agents: int
    approved_agents: int
    pending_approval: int
    total_scans: int
    scans_passed: int
    scans_failed: int
    events_last_24h: int
    critical_events_last_24h: int
    top_risk_agents: List[dict]
    event_breakdown: dict


class GalactusQueryRequest(BaseModel):
    question: str
    agent_id: Optional[str] = None   # scope context to one agent (optional)
    mode: Optional[str] = None       # "bedrock" | "agentcore" — overrides env var
    model_id: Optional[str] = None   # override model for this request (bedrock mode only)
    session_id: Optional[str] = None # for multi-turn AgentCore conversations


class GalactusQueryResponse(BaseModel):
    answer: str
    mode: str
    model_id: Optional[str] = None   # model actually used (None for agentcore)
    session_id: str
    agent_id: Optional[str] = None


# ─────────────────────────────────────────
# Agent Registration & Management
# ─────────────────────────────────────────

@app.post("/api/v1/agents", response_model=AgentResponse, status_code=status.HTTP_201_CREATED,
          summary="Register an agent — triggers pre-deployment scan automatically")
def register_agent(req: AgentRegisterRequest, background_tasks: BackgroundTasks,
                   db: Session = Depends(get_db)):
    # Resolve provider: if bedrock fields supplied without provider, default to bedrock
    provider = req.provider
    provider_config = req.provider_config
    bedrock_model_id = req.bedrock_model_id
    bedrock_guardrail_id = req.bedrock_guardrail_id
    bedrock_guardrail_version = req.bedrock_guardrail_version

    if provider == 'bedrock' and provider_config:
        # Sync legacy fields from provider_config so existing tooling still works
        bedrock_model_id = provider_config.get('model_id') or bedrock_model_id
        bedrock_guardrail_id = provider_config.get('guardrail_id') or bedrock_guardrail_id
        bedrock_guardrail_version = provider_config.get('guardrail_version') or bedrock_guardrail_version
    elif not provider and bedrock_model_id:
        # Legacy registration without provider field — treat as bedrock
        provider = 'bedrock'
        provider_config = {
            'model_id': bedrock_model_id,
            'guardrail_id': bedrock_guardrail_id,
            'guardrail_version': bedrock_guardrail_version,
        }

    agent = Agent(
        name=req.name,
        team_name=req.team_name,
        owner_email=req.owner_email,
        slack_channel=req.slack_channel,
        endpoint_url=req.endpoint_url,
        bedrock_model_id=bedrock_model_id,
        framework=req.framework,
        mcp_servers=[s.model_dump() for s in req.mcp_servers],
        allowed_tools=req.allowed_tools,
        bedrock_guardrail_id=bedrock_guardrail_id,
        bedrock_guardrail_version=bedrock_guardrail_version,
        provider=provider,
        provider_config=provider_config,
        nemo_guardrails_config=req.nemo_guardrails_config,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)

    # Default alert config scoped to the owner
    db.add(AlertConfig(agent_id=agent.id, email_recipients=[req.owner_email]))
    db.commit()

    # Queue the red-team scan
    background_tasks.add_task(trigger_scan_task, str(agent.id), "registration")

    return agent


@app.get("/api/v1/agents", response_model=List[AgentResponse])
def list_agents(team_name: Optional[str] = None, approved_only: bool = False,
                db: Session = Depends(get_db)):
    q = db.query(Agent).filter(Agent.is_active == True)
    if team_name:
        q = q.filter(Agent.team_name == team_name)
    if approved_only:
        q = q.filter(Agent.is_approved == True)
    return q.order_by(desc(Agent.created_at)).all()


@app.get("/api/v1/agents/{agent_id}", response_model=AgentResponse)
def get_agent(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@app.delete("/api/v1/agents/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_agent(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.is_active = False
    db.commit()


# ─────────────────────────────────────────
# Scan Management
# ─────────────────────────────────────────

@app.post("/api/v1/agents/{agent_id}/scans", status_code=status.HTTP_202_ACCEPTED,
          summary="Manually trigger a red-team scan")
def trigger_scan(agent_id: str, background_tasks: BackgroundTasks,
                 db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    background_tasks.add_task(trigger_scan_task, agent_id, "manual")
    return {"message": "Scan queued", "agent_id": agent_id}


@app.get("/api/v1/agents/{agent_id}/scans", response_model=List[ScanResponse])
def get_scan_history(agent_id: str, limit: int = 10, db: Session = Depends(get_db)):
    return (
        db.query(ScanResult)
        .filter(ScanResult.agent_id == agent_id)
        .order_by(desc(ScanResult.created_at))
        .limit(limit)
        .all()
    )


@app.get("/api/v1/agents/{agent_id}/scans/{scan_id}", response_model=ScanResponse)
def get_scan(agent_id: str, scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanResult).filter(
        ScanResult.id == scan_id, ScanResult.agent_id == agent_id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ─────────────────────────────────────────
# Runtime Event Ingestion
# ─────────────────────────────────────────

@app.post("/api/v1/events", status_code=status.HTTP_201_CREATED,
          summary="Ingest a runtime security event from Bedrock Guardrails / LLM Guard / LlamaFirewall")
def ingest_event(event: GuardrailEventIngest, background_tasks: BackgroundTasks,
                 db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == event.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    ge = GuardrailEvent(
        agent_id=event.agent_id,
        event_type=event.event_type,
        severity=SeverityLevel(event.severity),
        source=event.source,
        details=event.details,
        blocked=event.blocked,
        session_id=event.session_id,
        input_hash=event.input_hash,
    )
    db.add(ge)
    db.commit()
    db.refresh(ge)

    background_tasks.add_task(_check_and_alert, str(agent.id), event.event_type, event.severity)

    return {"id": str(ge.id), "status": "recorded"}


@app.get("/api/v1/events", response_model=List[GuardrailEventResponse])
def list_events(
    agent_id: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    hours: int = 24,
    limit: int = 200,
    db: Session = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = db.query(GuardrailEvent).filter(GuardrailEvent.occurred_at >= since)
    if agent_id:
        q = q.filter(GuardrailEvent.agent_id == agent_id)
    if severity:
        q = q.filter(GuardrailEvent.severity == SeverityLevel(severity))
    if event_type:
        q = q.filter(GuardrailEvent.event_type == event_type)
    return q.order_by(desc(GuardrailEvent.occurred_at)).limit(limit).all()


# ─────────────────────────────────────────
# Cross-team Dashboard
# ─────────────────────────────────────────

@app.get("/api/v1/dashboard", response_model=DashboardMetrics)
def dashboard(db: Session = Depends(get_db)):
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)

    total = db.query(Agent).filter(Agent.is_active == True).count()
    approved = db.query(Agent).filter(Agent.is_active == True, Agent.is_approved == True).count()

    total_scans = db.query(ScanResult).count()
    passed = db.query(ScanResult).filter(ScanResult.gate_passed == True).count()
    failed = db.query(ScanResult).filter(ScanResult.gate_passed == False).count()

    events_24h = db.query(GuardrailEvent).filter(GuardrailEvent.occurred_at >= since_24h).count()
    critical_24h = db.query(GuardrailEvent).filter(
        GuardrailEvent.occurred_at >= since_24h,
        GuardrailEvent.severity == SeverityLevel.CRITICAL
    ).count()

    breakdown = {
        row[0]: row[1]
        for row in db.query(GuardrailEvent.event_type, func.count(GuardrailEvent.id))
        .filter(GuardrailEvent.occurred_at >= since_24h)
        .group_by(GuardrailEvent.event_type)
        .all()
    }

    risk_rows = (
        db.query(GuardrailEvent.agent_id, func.count(GuardrailEvent.id).label("cnt"))
        .filter(GuardrailEvent.occurred_at >= since_24h)
        .group_by(GuardrailEvent.agent_id)
        .order_by(desc("cnt"))
        .limit(5)
        .all()
    )
    top_risk = []
    for row in risk_rows:
        a = db.query(Agent).filter(Agent.id == row[0]).first()
        if a:
            top_risk.append({"agent_id": str(a.id), "name": a.name, "team": a.team_name, "event_count": row[1]})

    return DashboardMetrics(
        total_agents=total, approved_agents=approved, pending_approval=total - approved,
        total_scans=total_scans, scans_passed=passed, scans_failed=failed,
        events_last_24h=events_24h, critical_events_last_24h=critical_24h,
        top_risk_agents=top_risk, event_breakdown=breakdown,
    )


# ─────────────────────────────────────────
# Galactus — AI Security Intelligence
# ─────────────────────────────────────────

@app.post(
    "/api/v1/galactus/query",
    response_model=GalactusQueryResponse,
    summary="Ask Galactus — AI security analysis for agents, scan failures, and remediation",
)
def galactus_query(req: GalactusQueryRequest, db: Session = Depends(get_db)):
    """
    Natural-language infosec Q&A powered by AWS Bedrock (or Bedrock AgentCore).

    - Set **agent_id** to scope the context to a single agent's scan results and events.
    - Leave **agent_id** empty for fleet-wide questions (posture, trends, top risks).
    - Use **mode** to override the GALACTUS_MODE env var for a single request.
    - Pass **session_id** to continue a multi-turn AgentCore conversation.
    """
    try:
        result = galactus_engine.query(
            question=req.question,
            db=db,
            agent_id=req.agent_id,
            mode=req.mode,
            model_id=req.model_id,
            session_id=req.session_id,
        )
        return GalactusQueryResponse(**result)
    except ModuleNotFoundError as e:
        raise HTTPException(
            status_code=503,
            detail=f"boto3 not installed. Run: pip install boto3  ({e})",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Galactus error: {e}")


@app.get(
    "/api/v1/galactus/models",
    summary="List available Bedrock Claude models for Galactus",
)
def galactus_models():
    """
    Returns Claude models available for on-demand inference in the configured region.
    Queries Bedrock's ListFoundationModels API live; falls back to a curated list
    when credentials are not yet available (e.g. local dev without AWS keys).
    Models are sorted latest-first by version date.
    """
    try:
        return galactus_engine.list_models()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/api/v1/galactus/insight",
    summary="AI-generated fleet security overview — main dashboard analytics widget",
)
def galactus_insight(
    model_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Returns a concise AI-generated security overview for the entire agent fleet.
    Powered by Galactus (AWS Bedrock). Intended for the main dashboard analytics widget.

    The client should cache this result for ~5 minutes to avoid unnecessary API calls.
    Pass **model_id** to override the default Galactus model for this request.
    """
    FLEET_INSIGHT_PROMPT = (
        "You are a senior AI security analyst reviewing the current state of the agent fleet. "
        "Provide a concise, actionable security briefing covering:\n"
        "1. Agents with the highest risk — name them with their scores and the specific OWASP "
        "categories they failed\n"
        "2. The most critical vulnerability patterns across the fleet\n"
        "3. Runtime attack activity in the last 24 hours (if any)\n"
        "4. Top 3 priority actions the security team should take right now\n\n"
        "Be direct and specific. Use agent names. Limit response to 300 words."
    )
    try:
        result = galactus_engine.query(
            question=FLEET_INSIGHT_PROMPT,
            db=db,
            agent_id=None,   # fleet-level context
            mode=None,        # use configured default
            model_id=model_id,
            session_id=None,
        )
        return {
            "summary": result["answer"],
            "model_id": result.get("model_id"),
            "mode": result.get("mode"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    except ModuleNotFoundError as e:
        raise HTTPException(
            status_code=503,
            detail=f"boto3 not installed. Run: pip install boto3  ({e})",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Galactus insight error: {e}")


@app.get(
    "/api/v1/galactus/status",
    summary="Galactus configuration and connectivity status",
)
def galactus_status():
    """Returns current Galactus configuration — useful for UI feature gating."""
    return {
        "enabled": True,
        "mode": settings.GALACTUS_MODE,
        "model_id": settings.GALACTUS_MODEL_ID,
        "agentcore_configured": bool(
            settings.GALACTUS_AGENT_ID and settings.GALACTUS_AGENT_ALIAS_ID
        ),
        "aws_credentials": (
            "explicit_env_vars" if settings.AWS_ACCESS_KEY_ID else "instance_profile_or_default"
        ),
        "aws_region": settings.AWS_REGION,
    }


# ─────────────────────────────────────────
# Settings API
# ─────────────────────────────────────────

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "admin"


class ChangePasswordRequest(BaseModel):
    new_password: str


@app.get("/api/v1/settings/platform", summary="Platform configuration and status")
def settings_platform():
    return {
        "app_env": settings.APP_ENV,
        "mock_scan": settings.MOCK_SCAN,
        "auth_mode": settings.AUTH_MODE,
        "aws_region": settings.AWS_REGION,
        "aws_credentials": "explicit" if settings.AWS_ACCESS_KEY_ID else "instance_profile_or_default",
        "galactus_mode": settings.GALACTUS_MODE,
        "galactus_model": settings.GALACTUS_MODEL_ID,
        "agentcore_configured": bool(settings.GALACTUS_AGENT_ID and settings.GALACTUS_AGENT_ALIAS_ID),
        "jwt_expire_minutes": settings.JWT_EXPIRE_MINUTES,
        "version": "1.0.0",
    }


class ScanModeRequest(BaseModel):
    mode: str  # 'mock' | 'promptfoo' | 'nemo'


@app.get("/api/v1/settings/scan-mode", summary="Current scan engine mode")
def settings_get_scan_mode():
    mode = get_scan_mode()
    return {
        "mode": mode,
        "mock_scan": mode == "mock",
        "label": {
            "mock":      "Mock Scan — 46 direct probes, no API keys required",
            "promptfoo": "Promptfoo Full Scan — 50+ LLM-generated red-team attacks",
            "nemo":      "NeMo Guardrails — structured rails evaluation via NeMo agent",
        }.get(mode, mode),
    }


@app.post("/api/v1/settings/scan-mode", summary="Update scan engine mode at runtime")
def settings_set_scan_mode(req: ScanModeRequest):
    valid = ("mock", "promptfoo", "nemo")
    if req.mode not in valid:
        raise HTTPException(status_code=400, detail=f"mode must be one of {valid}")
    try:
        set_scan_mode(req.mode)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"mode": req.mode, "ok": True}


@app.get("/api/v1/settings/thresholds", summary="Current gate threshold values")
def settings_thresholds():
    return {
        "prompt_injection":     {"value": settings.PROMPT_INJECTION_THRESHOLD,     "tolerance": "zero"},
        "jailbreak":            {"value": settings.JAILBREAK_THRESHOLD,            "tolerance": "zero"},
        "system_prompt_leakage":{"value": settings.SYSTEM_PROMPT_LEAKAGE_THRESHOLD,"tolerance": "zero"},
        "excessive_agency":     {"value": settings.EXCESSIVE_AGENCY_THRESHOLD,     "tolerance": "zero"},
        "mcp_poisoning":        {"value": settings.MCP_POISONING_THRESHOLD,        "tolerance": "zero"},
        "pii_leak":             {"value": settings.PII_LEAK_THRESHOLD,             "tolerance": "permissive"},
        "insecure_output":      {"value": settings.INSECURE_OUTPUT_THRESHOLD,      "tolerance": "permissive"},
        "content_violation":    {"value": settings.CONTENT_VIOLATION_THRESHOLD,    "tolerance": "permissive"},
        "misinformation":       {"value": settings.MISINFORMATION_THRESHOLD,       "tolerance": "permissive"},
    }


@app.get("/api/v1/settings/users", summary="List platform users")
def settings_list_users(db: Session = Depends(get_db)):
    return list_users(db)


@app.post("/api/v1/settings/users", status_code=status.HTTP_201_CREATED,
          summary="Create a platform user")
def settings_create_user(req: CreateUserRequest, db: Session = Depends(get_db)):
    if not req.username or len(req.username) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters")
    if not req.password or len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if req.role not in ("admin", "analyst"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'analyst'")
    try:
        return create_user(req.username, req.password, req.role, db)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.put("/api/v1/settings/users/{username}/password",
         summary="Change a user's password")
def settings_change_password(username: str, req: ChangePasswordRequest,
                              db: Session = Depends(get_db)):
    if not req.new_password or len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    try:
        update_password(username, req.new_password, db)
        return {"status": "ok"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/api/v1/settings/users/{username}", status_code=status.HTTP_204_NO_CONTENT,
            summary="Deactivate a platform user")
def settings_delete_user(username: str, db: Session = Depends(get_db)):
    try:
        delete_user(username, db)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ─────────────────────────────────────────
# Health
# ─────────────────────────────────────────

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok", "service": "ai-watchtower-api", "mock_scan": settings.MOCK_SCAN}


# ─────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────

async def _check_and_alert(agent_id: str, event_type: str, severity: str):
    from database import SessionLocal
    db = SessionLocal()
    try:
        since_1h = datetime.now(timezone.utc) - timedelta(hours=1)
        count = db.query(GuardrailEvent).filter(
            GuardrailEvent.agent_id == agent_id,
            GuardrailEvent.event_type == event_type,
            GuardrailEvent.occurred_at >= since_1h,
        ).count()

        cfg = db.query(AlertConfig).filter(AlertConfig.agent_id == agent_id).first()
        if not cfg:
            return

        threshold = {"prompt_injection": cfg.prompt_injection_alert_threshold,
                     "pii": cfg.pii_leak_alert_threshold}.get(event_type, 5.0)

        if count >= threshold or severity == "critical":
            agent = db.query(Agent).filter(Agent.id == agent_id).first()
            if agent:
                await send_alert(
                    agent=agent, alert_cfg=cfg,
                    message=(f"🚨 *{agent.name}* ({agent.team_name}) — "
                             f"{count}x `{event_type}` in last hour (severity: {severity})"),
                )
    finally:
        db.close()
