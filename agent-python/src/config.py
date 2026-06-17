from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import os
from typing import Any, Dict, List
from urllib.parse import urlsplit

try:
    from dotenv import load_dotenv
except Exception:
    def load_dotenv(*_args, **_kwargs):
        return False


BASE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BASE_DIR.parent
REDACTED_VALUE = "***"
SECRET_KEY_MARKERS = ("api_key", "apikey", "token", "secret", "password", "credential")

# Load local environment files without requiring secrets to be committed.
# Later files override earlier values only when variables are not already set by the shell.
for env_path in (PROJECT_ROOT / ".env", BASE_DIR / ".env"):
    load_dotenv(dotenv_path=env_path, override=False)


def _csv_env(name: str, default: str = "") -> List[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


def _optional_env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _first_non_empty(*names: str) -> str | None:
    for name in names:
        value = _optional_env(name)
        if value:
            return value
    return None


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class DatabaseConfig:
    mongo_uri: str = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017")
    server_selection_timeout_ms: int = _int_env("MONGO_SERVER_SELECTION_TIMEOUT_MS", 1500)
    connect_timeout_ms: int = _int_env("MONGO_CONNECT_TIMEOUT_MS", 1500)
    db_name: str = os.getenv("DB_NAME", "threat_intel")


@dataclass(frozen=True)
class LLMConfig:
    enabled: bool = field(default_factory=lambda: _bool_env("LLM_ENABLED", False))

    # Preferred provider-neutral variables. OPENAI_* remains for backward compatibility.
    api_key: str | None = field(default_factory=lambda: _first_non_empty("LLM_API_KEY", "OPENAI_API_KEY"))
    base_url: str | None = field(default_factory=lambda: _first_non_empty("LLM_BASE_URL", "OPENAI_BASE_URL"))
    model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", "gpt-4o-mini"))

    timeout_seconds: int = field(default_factory=lambda: _int_env("LLM_TIMEOUT_SECONDS", 10))
    max_input_chars: int = field(default_factory=lambda: _int_env("LLM_MAX_INPUT_CHARS", 4000))
    max_retries: int = field(default_factory=lambda: _int_env("LLM_MAX_RETRIES", 2))
    debug: bool = field(default_factory=lambda: _bool_env("LLM_DEBUG", False))

    @property
    def is_configured(self) -> bool:
        return bool(self.enabled and self.api_key)


@dataclass(frozen=True)
class RuntimeConfig:
    default_batch_size: int = _int_env("DEFAULT_BATCH_SIZE", 20)
    default_idle_sleep: int = _int_env("DEFAULT_IDLE_SLEEP", 10)
    default_active_sleep: int = _int_env("DEFAULT_ACTIVE_SLEEP", 5)
    default_report_limit: int = _int_env("DEFAULT_REPORT_LIMIT", 5)


@dataclass(frozen=True)
class ScoreWeights:
    base_cvss_multiplier: float = _float_env("BASE_CVSS_MULTIPLIER", 0.72)
    zero_cvss_fallback: float = _float_env("ZERO_CVSS_FALLBACK", 1.5)
    graph_bonus_multiplier: float = _float_env("GRAPH_BONUS_MULTIPLIER", 0.55)
    graph_bonus_cap: float = _float_env("GRAPH_BONUS_CAP", 0.6)
    urlhaus_score_cap: float = _float_env("URLHAUS_SCORE_CAP", 2.8)
    dread_score_cap: float = _float_env("DREAD_SCORE_CAP", 2.5)
    llm_bonus_cap: float = _float_env("LLM_BONUS_CAP", 0.8)
    lexical_weight: float = _float_env("CORRELATION_LEXICAL_WEIGHT", 0.45)
    semantic_weight: float = _float_env("CORRELATION_SEMANTIC_WEIGHT", 0.35)
    temporal_weight: float = _float_env("CORRELATION_TEMPORAL_WEIGHT", 0.20)
    entity_weight: float = _float_env("CORRELATION_ENTITY_WEIGHT", 0.25)
    high_signal_weight: float = _float_env("CORRELATION_HIGH_SIGNAL_WEIGHT", 0.30)
    online_weight: float = _float_env("CORRELATION_ONLINE_WEIGHT", 0.12)
    recentness_0_3_days: float = _float_env("RECENTNESS_0_3_DAYS", 1.2)
    recentness_4_14_days: float = _float_env("RECENTNESS_4_14_DAYS", 0.8)
    recentness_15_30_days: float = _float_env("RECENTNESS_15_30_DAYS", 0.4)
    age_penalty_90_plus: float = _float_env("AGE_PENALTY_90_PLUS", 0.15)
    age_penalty_365_plus: float = _float_env("AGE_PENALTY_365_PLUS", 0.45)
    age_penalty_1825_plus: float = _float_env("AGE_PENALTY_1825_PLUS", 0.75)
    age_penalty_3650_plus: float = _float_env("AGE_PENALTY_3650_PLUS", 1.0)
    critical_threshold: float = _float_env("CRITICAL_THRESHOLD", 8.5)
    high_threshold: float = _float_env("HIGH_THRESHOLD", 6.5)
    medium_threshold: float = _float_env("MEDIUM_THRESHOLD", 4.0)


@dataclass(frozen=True)
class RetrievalConfig:
    max_keyword_terms: int = _int_env("MAX_KEYWORD_TERMS", 12)
    candidate_limit: int = _int_env("CANDIDATE_LIMIT", 25)
    search_field_limit: int = _int_env("SEARCH_FIELD_LIMIT", 10)

    min_shared_terms: int = _int_env("MIN_SHARED_TERMS", 2)
    min_lexical_overlap: float = _float_env("MIN_LEXICAL_OVERLAP", 0.08)
    min_semantic_support: float = _float_env("MIN_SEMANTIC_SUPPORT", 0.22)


@dataclass(frozen=True)
class SemanticConfig:
    enabled: bool = os.getenv("SEMANTIC_ENABLED", "1") not in {"0", "false", "False"}
    backend: str = os.getenv("SEMANTIC_BACKEND", "fallback")
    model_name: str = os.getenv("SEMANTIC_MODEL", "all-MiniLM-L6-v2")
    allow_remote_model_download: bool = os.getenv("SEMANTIC_ALLOW_DOWNLOAD", "0") in {"1", "true", "True"}
    similarity_floor: float = _float_env("SEMANTIC_SIMILARITY_FLOOR", 0.22)


@dataclass(frozen=True)
class APIConfig:
    cors_origins: List[str] = field(default_factory=lambda: _csv_env("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"))


@dataclass(frozen=True)
class SecurityConfig:
    auth_mode: str = field(default_factory=lambda: os.getenv("API_AUTH_MODE", "development").strip().lower())
    api_keys: List[str] = field(default_factory=lambda: _csv_env("API_KEYS", ""))
    development_actor_id: str = field(default_factory=lambda: os.getenv("API_DEV_ACTOR_ID", "local-dev"))
    development_role_name: str = field(default_factory=lambda: os.getenv("API_DEV_ROLE", "admin").strip().lower())


@dataclass(frozen=True)
class DreadConfig:
    enabled: bool = field(default_factory=lambda: _bool_env("DREAD_ENABLED", False))
    onion_url: str | None = field(default_factory=lambda: _optional_env("DREAD_ONION_URL"))
    request_timeout_seconds: int = field(default_factory=lambda: _int_env("DREAD_REQUEST_TIMEOUT_SECONDS", 90))


@dataclass(frozen=True)
class AppSettings:
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    api: APIConfig = field(default_factory=APIConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    scoring: ScoreWeights = field(default_factory=ScoreWeights)
    retrieval: RetrievalConfig = field(default_factory=RetrievalConfig)
    semantic: SemanticConfig = field(default_factory=SemanticConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    dread: DreadConfig = field(default_factory=DreadConfig)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_public_dict(self) -> Dict[str, Any]:
        return _redact_public_settings(asdict(self))

    @property
    def mongo(self) -> DatabaseConfig:
        return self.database


def _redact_public_settings(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        redacted: Dict[str, Any] = {}
        for item_key, item_value in value.items():
            normalized_key = str(item_key)
            if normalized_key == "mongo_uri":
                redacted[normalized_key] = REDACTED_VALUE if item_value else None
                redacted["mongo_uri_configured"] = bool(item_value)
                continue
            if _is_secret_setting_key(normalized_key):
                redacted[normalized_key] = REDACTED_VALUE if item_value else None
                redacted[f"{normalized_key}_configured"] = bool(item_value)
                continue
            if isinstance(item_value, str) and _uri_contains_credentials(item_value):
                redacted[normalized_key] = REDACTED_VALUE
                redacted[f"{normalized_key}_configured"] = True
                continue
            redacted[normalized_key] = _redact_public_settings(item_value, normalized_key)
        return redacted
    if isinstance(value, list):
        return [_redact_public_settings(item, key) for item in value]
    if isinstance(value, tuple):
        return [_redact_public_settings(item, key) for item in value]
    if isinstance(value, str) and _uri_contains_credentials(value):
        return REDACTED_VALUE
    return value


def _is_secret_setting_key(key: str) -> bool:
    lowered = key.lower()
    if lowered.endswith("_configured"):
        return False
    return any(marker in lowered for marker in SECRET_KEY_MARKERS)


def _uri_contains_credentials(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.scheme and parsed.netloc and (parsed.username or parsed.password))


SETTINGS = AppSettings()

MONGO_URI = SETTINGS.database.mongo_uri
DB_NAME = SETTINGS.database.db_name

# Preferred provider-neutral names.
LLM_ENABLED = SETTINGS.llm.enabled
LLM_API_KEY = SETTINGS.llm.api_key
LLM_BASE_URL = SETTINGS.llm.base_url
LLM_MODEL = SETTINGS.llm.model
LLM_TIMEOUT_SECONDS = SETTINGS.llm.timeout_seconds
LLM_MAX_INPUT_CHARS = SETTINGS.llm.max_input_chars
LLM_MAX_RETRIES = SETTINGS.llm.max_retries
LLM_DEBUG = SETTINGS.llm.debug

# Legacy names kept for existing imports.
OPENAI_API_KEY = SETTINGS.llm.api_key
OPENAI_BASE_URL = SETTINGS.llm.base_url

DEFAULT_BATCH_SIZE = SETTINGS.runtime.default_batch_size
DEFAULT_IDLE_SLEEP = SETTINGS.runtime.default_idle_sleep
DEFAULT_ACTIVE_SLEEP = SETTINGS.runtime.default_active_sleep
DEFAULT_REPORT_LIMIT = SETTINGS.runtime.default_report_limit
APP_VERSION = os.getenv("APP_VERSION", "0.4.0")
DREAD_ENABLED = SETTINGS.dread.enabled
DREAD_ONION_URL = SETTINGS.dread.onion_url
DREAD_REQUEST_TIMEOUT_SECONDS = SETTINGS.dread.request_timeout_seconds


def get_settings() -> AppSettings:
    return SETTINGS
