from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import os
from typing import Any, Dict

try:
    from dotenv import load_dotenv
except Exception:
    def load_dotenv(*_args, **_kwargs):
        return False


BASE_DIR = Path(__file__).resolve().parents[1]
ENV_PATH = BASE_DIR.parent / ".env"

load_dotenv(dotenv_path=ENV_PATH)


@dataclass(frozen=True)
class DatabaseConfig:
    mongo_uri: str = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017")
    server_selection_timeout_ms: int = int(os.getenv("MONGO_SERVER_SELECTION_TIMEOUT_MS", "1500"))
    connect_timeout_ms: int = int(os.getenv("MONGO_CONNECT_TIMEOUT_MS", "1500"))
    db_name: str = os.getenv("DB_NAME", "threat_intel")


@dataclass(frozen=True)
class LLMConfig:
    api_key: str | None = os.getenv("OPENAI_API_KEY")
    base_url: str | None = os.getenv("OPENAI_BASE_URL")
    model: str = os.getenv("LLM_MODEL", "gpt-4o-mini")


@dataclass(frozen=True)
class RuntimeConfig:
    default_batch_size: int = int(os.getenv("DEFAULT_BATCH_SIZE", "20"))
    default_idle_sleep: int = int(os.getenv("DEFAULT_IDLE_SLEEP", "10"))
    default_active_sleep: int = int(os.getenv("DEFAULT_ACTIVE_SLEEP", "5"))
    default_report_limit: int = int(os.getenv("DEFAULT_REPORT_LIMIT", "5"))


@dataclass(frozen=True)
class ScoreWeights:
    base_cvss_multiplier: float = float(os.getenv("BASE_CVSS_MULTIPLIER", "0.55"))
    zero_cvss_fallback: float = float(os.getenv("ZERO_CVSS_FALLBACK", "1.5"))
    graph_bonus_multiplier: float = float(os.getenv("GRAPH_BONUS_MULTIPLIER", "0.55"))
    graph_bonus_cap: float = float(os.getenv("GRAPH_BONUS_CAP", "0.6"))
    urlhaus_score_cap: float = float(os.getenv("URLHAUS_SCORE_CAP", "2.8"))
    dread_score_cap: float = float(os.getenv("DREAD_SCORE_CAP", "2.5"))
    llm_bonus_cap: float = float(os.getenv("LLM_BONUS_CAP", "0.8"))
    lexical_weight: float = float(os.getenv("CORRELATION_LEXICAL_WEIGHT", "0.45"))
    semantic_weight: float = float(os.getenv("CORRELATION_SEMANTIC_WEIGHT", "0.35"))
    temporal_weight: float = float(os.getenv("CORRELATION_TEMPORAL_WEIGHT", "0.20"))
    entity_weight: float = float(os.getenv("CORRELATION_ENTITY_WEIGHT", "0.25"))
    high_signal_weight: float = float(os.getenv("CORRELATION_HIGH_SIGNAL_WEIGHT", "0.30"))
    online_weight: float = float(os.getenv("CORRELATION_ONLINE_WEIGHT", "0.12"))
    recentness_0_3_days: float = float(os.getenv("RECENTNESS_0_3_DAYS", "1.2"))
    recentness_4_14_days: float = float(os.getenv("RECENTNESS_4_14_DAYS", "0.8"))
    recentness_15_30_days: float = float(os.getenv("RECENTNESS_15_30_DAYS", "0.4"))
    age_penalty_90_plus: float = float(os.getenv("AGE_PENALTY_90_PLUS", "0.8"))
    age_penalty_365_plus: float = float(os.getenv("AGE_PENALTY_365_PLUS", "1.8"))
    age_penalty_1825_plus: float = float(os.getenv("AGE_PENALTY_1825_PLUS", "2.5"))
    age_penalty_3650_plus: float = float(os.getenv("AGE_PENALTY_3650_PLUS", "3.0"))
    critical_threshold: float = float(os.getenv("CRITICAL_THRESHOLD", "8.5"))
    high_threshold: float = float(os.getenv("HIGH_THRESHOLD", "7.0"))
    medium_threshold: float = float(os.getenv("MEDIUM_THRESHOLD", "4.5"))


@dataclass(frozen=True)
class RetrievalConfig:
    max_keyword_terms: int = int(os.getenv("MAX_KEYWORD_TERMS", "12"))
    candidate_limit: int = int(os.getenv("CANDIDATE_LIMIT", "25"))
    search_field_limit: int = int(os.getenv("SEARCH_FIELD_LIMIT", "10"))

    min_shared_terms: int = int(os.getenv("MIN_SHARED_TERMS", "2"))
    min_lexical_overlap: float = float(os.getenv("MIN_LEXICAL_OVERLAP", "0.08"))
    min_semantic_support: float = float(os.getenv("MIN_SEMANTIC_SUPPORT", "0.22"))


@dataclass(frozen=True)
class SemanticConfig:
    enabled: bool = os.getenv("SEMANTIC_ENABLED", "1") not in {"0", "false", "False"}
    backend: str = os.getenv("SEMANTIC_BACKEND", "fallback")
    model_name: str = os.getenv("SEMANTIC_MODEL", "all-MiniLM-L6-v2")
    allow_remote_model_download: bool = os.getenv("SEMANTIC_ALLOW_DOWNLOAD", "0") in {"1", "true", "True"}
    similarity_floor: float = float(os.getenv("SEMANTIC_SIMILARITY_FLOOR", "0.22"))


@dataclass(frozen=True)
class AppSettings:
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    scoring: ScoreWeights = field(default_factory=ScoreWeights)
    retrieval: RetrievalConfig = field(default_factory=RetrievalConfig)
    semantic: SemanticConfig = field(default_factory=SemanticConfig)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


SETTINGS = AppSettings()

MONGO_URI = SETTINGS.database.mongo_uri
DB_NAME = SETTINGS.database.db_name
OPENAI_API_KEY = SETTINGS.llm.api_key
OPENAI_BASE_URL = SETTINGS.llm.base_url
LLM_MODEL = SETTINGS.llm.model
DEFAULT_BATCH_SIZE = SETTINGS.runtime.default_batch_size
DEFAULT_IDLE_SLEEP = SETTINGS.runtime.default_idle_sleep
DEFAULT_ACTIVE_SLEEP = SETTINGS.runtime.default_active_sleep
DEFAULT_REPORT_LIMIT = SETTINGS.runtime.default_report_limit
APP_VERSION = os.getenv("APP_VERSION", "0.4.0")


def get_settings() -> AppSettings:
    return SETTINGS
