from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Protocol


class AuditOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


@dataclass(frozen=True)
class AuditEvent:
    actor_id: str
    role: str
    action: str
    target: str
    outcome: AuditOutcome
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "role": self.role,
            "action": self.action,
            "target": self.target,
            "outcome": self.outcome.value,
            "timestamp": self.timestamp.isoformat(),
            "details": sanitize_audit_details(self.details),
        }


class AuditSink(Protocol):
    def write(self, event: AuditEvent) -> None:
        ...


class StructuredAuditLogger:
    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger or logging.getLogger("api.audit")
        self.events: List[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)
        self.logger.info("audit_event=%s", event.to_dict())


def sanitize_audit_details(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): sanitize_audit_details(item) for key, item in value.items() if not _secret_key(str(key))}
    if isinstance(value, list):
        return [sanitize_audit_details(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_audit_details(item) for item in value]
    if isinstance(value, BaseException):
        return type(value).__name__
    return value


def _secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("authorization", "api_key", "apikey", "token", "secret", "password"))
