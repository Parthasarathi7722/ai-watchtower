from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from config import settings

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from models import Agent, ScanResult, GuardrailEvent, AlertConfig, WatchtowerUser  # noqa
    Base.metadata.create_all(bind=engine)

    # Idempotent column additions — safe to run on every restart (IF NOT EXISTS).
    # Handles upgrades without Alembic for local / Docker Compose deployments.
    _migrations = [
        # Vendor-agnostic provider identity on Agent
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS provider VARCHAR(50)",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS provider_config JSONB",
        # New OWASP score columns on ScanResult
        "ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS system_prompt_leakage_score FLOAT",
        "ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS excessive_agency_score FLOAT",
        "ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS insecure_output_score FLOAT",
        # Rich per-probe findings stored separately from raw_report
        "ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS findings JSONB",
        # LLM09 misinformation score
        "ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS misinformation_score FLOAT",
        # Provider-specific guardrail recommendations
        "ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS guardrail_config JSONB",
        # NeMo Guardrails runtime config on Agent
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS nemo_guardrails_config JSONB",
    ]
    with engine.begin() as conn:
        for stmt in _migrations:
            conn.execute(text(stmt))

    _seed_users()


def _seed_users():
    """
    On first boot (empty watchtower_users table), create the initial admin user.
    Source priority: Secrets Manager → local env vars.
    On subsequent boots the DB is the source of truth — env vars are ignored.
    """
    import logging
    from models import WatchtowerUser
    logger = logging.getLogger(__name__)

    db = SessionLocal()
    try:
        if db.query(WatchtowerUser).count() > 0:
            return  # users already exist — DB is the source of truth

        from auth import load_credentials
        creds = load_credentials()
        for username, password_hash in creds.items():
            db.add(WatchtowerUser(username=username, password_hash=password_hash, role="admin"))
        db.commit()
        logger.info("AUTH: Seeded %d initial user(s) into watchtower_users", len(creds))
    finally:
        db.close()
