import os
from urllib.parse import quote_plus

from dotenv import load_dotenv

load_dotenv()


def _database_uri() -> str:
    """DATABASE_URL wins (tests/CI); otherwise build a PostgreSQL URI from DB_* vars.

    Credentials are URL-quoted so passwords containing '@', ':' or '/' still work.
    """
    url = os.getenv("DATABASE_URL")
    if url:
        return url
    user = quote_plus(os.getenv("DB_USER", "oculus_user"))
    password = quote_plus(os.getenv("DB_PASSWORD", ""))
    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "5432")
    name = os.getenv("DB_NAME", "oculus_db")
    # psycopg v3 driver (no C build tools needed on Windows)
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{name}"


DEFAULT_SECRET = "dev-only-insecure-key"


class Config:
    DEBUG = os.getenv("FLASK_ENV") == "development"
    # Demo mode shows one-click demo sign-ins on the login page (fictional seeded accounts only). Never enable in production.
    DEMO_MODE = os.getenv("OCULUS_DEMO_MODE", "").lower() in ("1", "true") or os.getenv("FLASK_ENV") == "development"
    SECRET_KEY = os.getenv("SECRET_KEY", DEFAULT_SECRET)
    SQLALCHEMY_DATABASE_URI = _database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BCRYPT_ROUNDS = 12

    # --- Authentication (JWT in an httpOnly cookie, or Bearer header for API clients)
    JWT_EXPIRES_MINUTES = 30
    COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"  # set true behind HTTPS

    # --- Brute-force detection thresholds (counted from the security_events table)
    LOGIN_WINDOW_MINUTES = 15
    LOGIN_MAX_FAILURES = 5          # per (username, source IP) -> temporary lockout + incident
    LOGIN_IP_MAX_FAILURES = 20      # per source IP across all usernames -> password-spraying block

    # --- Detection engine / risk scoring
    DETECTION_WINDOW_MINUTES = 15        # sliding window for failed-login based rules
    RULE_SPRAY_DISTINCT_USERS = 5        # distinct usernames failing from one IP -> password spraying
    RULE_CRED_FAILURES = 3               # failures before a success -> possible credential compromise
    RULE_DENIED_COUNT = 3                # denied accesses ...
    RULE_DENIED_WINDOW_MINUTES = 30      # ... within this window -> reconnaissance / snooping
    RISK_INCIDENT_THRESHOLD = 70         # effective risk above this opens an insider-risk incident
    RISK_DECAY_PER_DAY = 5               # points of risk that fade per day without new violations
    TIMELINE_CONTEXT_MINUTES = 60        # how far around an incident to pull un-linked "context" events

    # --- Input policy
    ALLOWED_ROLES = ("Admin", "IT", "HR", "Finance", "Marketing", "Operations")
    PASSWORD_MIN_LENGTH = 8


class TestingConfig(Config):
    DEMO_MODE = False
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv("TEST_DATABASE_URL", "sqlite:///:memory:")
    SECRET_KEY = "test-secret-key"
    BCRYPT_ROUNDS = 4  # fast hashing in tests only
