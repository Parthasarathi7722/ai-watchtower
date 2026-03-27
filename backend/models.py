from sqlalchemy import Column, String, Float, Boolean, DateTime, JSON, Text, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timezone
import uuid
import enum

from database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


class SeverityLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Agent(Base):
    __tablename__ = "agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False)
    team_name = Column(String(100), nullable=False)
    owner_email = Column(String(200), nullable=False)
    slack_channel = Column(String(100), nullable=True)

    # Endpoint config
    endpoint_url = Column(String(500), nullable=False)
    bedrock_model_id = Column(String(200), nullable=True)
    framework = Column(String(100), nullable=True)  # langchain, crewai, etc.

    # MCP tools declared by the team
    mcp_servers = Column(JSON, default=list)       # [{"name": "slack", "url": "..."}]
    allowed_tools = Column(JSON, default=list)     # tool allowlist

    # Bedrock guardrail reference (kept for backward compat)
    bedrock_guardrail_id = Column(String(200), nullable=True)
    bedrock_guardrail_version = Column(String(50), nullable=True)

    # Vendor-agnostic provider identity
    # provider: openai | anthropic | ollama | openai_compatible | bedrock | custom
    provider = Column(String(50), nullable=True)
    # provider_config keys vary by provider:
    #   openai/anthropic:      { model, api_key_env }
    #   ollama:                { model, base_url }
    #   openai_compatible:     { model, base_url, api_key_env }
    #   bedrock:               { model_id, guardrail_id, guardrail_version, region }
    #   custom:                (none required)
    provider_config = Column(JSON, nullable=True)

    # NeMo Guardrails runtime protection config (optional, provider-agnostic)
    # Shape: {
    #   "enabled": bool,
    #   "server_url": str,    # http://nemo-guardrails:8000  (REST server)
    #   "config_path": str,   # /app/guardrails/my-agent/   (file-based config dir)
    #   "rails": list[str],   # ["input", "output", "execution", "retrieval"]
    # }
    nemo_guardrails_config = Column(JSON, nullable=True)

    # Status
    is_approved = Column(Boolean, default=False)   # passed pre-deploy gate
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))

    scans = relationship("ScanResult", back_populates="agent", cascade="all, delete-orphan")
    guardrail_events = relationship("GuardrailEvent", back_populates="agent", cascade="all, delete-orphan")
    alert_config = relationship("AlertConfig", back_populates="agent", uselist=False, cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False)

    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    triggered_by = Column(String(100), default="manual")  # manual | ci | scheduled

    # Scores (0–100, higher = more vulnerable)
    prompt_injection_score = Column(Float, nullable=True)
    pii_leak_score = Column(Float, nullable=True)
    jailbreak_score = Column(Float, nullable=True)
    content_violation_score = Column(Float, nullable=True)
    mcp_poisoning_score = Column(Float, nullable=True)
    overall_risk_score = Column(Float, nullable=True)
    # Expanded OWASP categories
    system_prompt_leakage_score = Column(Float, nullable=True)  # LLM07
    excessive_agency_score = Column(Float, nullable=True)       # LLM08
    insecure_output_score = Column(Float, nullable=True)        # LLM05
    misinformation_score = Column(Float, nullable=True)         # LLM09

    # OWASP mapping
    owasp_failures = Column(JSON, default=list)    # ["LLM01", "LLM06"]
    raw_report = Column(JSON, nullable=True)       # full promptfoo output
    summary = Column(Text, nullable=True)
    remediation_hints = Column(JSON, default=list)
    # Rich per-probe findings (pre-extracted from raw_report for API exposure)
    findings = Column(JSON, nullable=True)
    # Provider-specific guardrail recommendations generated from scan results
    guardrail_config = Column(JSON, nullable=True)

    gate_passed = Column(Boolean, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    agent = relationship("Agent", back_populates="scans")


class GuardrailEvent(Base):
    __tablename__ = "guardrail_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False)

    event_type = Column(String(100), nullable=False)   # prompt_injection | pii | jailbreak | tool_poisoning
    severity = Column(Enum(SeverityLevel), nullable=False)
    source = Column(String(100), nullable=False)       # bedrock_guardrails | llm_guard | llamafirewall | mcp_scanner
    input_hash = Column(String(64), nullable=True)     # sha256 of input (not raw content)
    details = Column(JSON, nullable=True)
    blocked = Column(Boolean, default=True)
    session_id = Column(String(200), nullable=True)
    occurred_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    agent = relationship("Agent", back_populates="guardrail_events")


class WatchtowerUser(Base):
    """Platform users — managed via Settings page or seeded from env vars / Secrets Manager."""
    __tablename__ = "watchtower_users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(200), nullable=False)
    role = Column(String(16), default="admin")   # admin | analyst (future)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime(timezone=True), nullable=True)


class AlertConfig(Base):
    __tablename__ = "alert_configs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False)

    slack_webhook = Column(String(500), nullable=True)
    email_recipients = Column(JSON, default=list)
    webhook_url = Column(String(500), nullable=True)

    # Alert thresholds (events per hour)
    prompt_injection_alert_threshold = Column(Float, default=1.0)
    pii_leak_alert_threshold = Column(Float, default=1.0)
    guardrail_spike_multiplier = Column(Float, default=3.0)  # 3x baseline = alert

    alert_on_scan_fail = Column(Boolean, default=True)
    alert_on_mcp_poisoning = Column(Boolean, default=True)

    agent = relationship("Agent", back_populates="alert_config")
