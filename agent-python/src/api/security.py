from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, Mapping, Optional

from fastapi import Depends, HTTPException, Request, status

from api.audit import AuditEvent, AuditOutcome, AuditSink
from config import SecurityConfig


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"


class Permission(str, Enum):
    READ_ANALYSES = "read_analyses"
    TRIGGER_ANALYSIS = "trigger_analysis"
    VIEW_JOBS = "view_jobs"
    ADMINISTER_SYSTEM = "administer_system"


ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.READ_ANALYSES}),
    Role.ANALYST: frozenset({Permission.READ_ANALYSES, Permission.TRIGGER_ANALYSIS}),
    Role.OPERATOR: frozenset({Permission.READ_ANALYSES, Permission.TRIGGER_ANALYSIS, Permission.VIEW_JOBS}),
    Role.ADMIN: frozenset({Permission.READ_ANALYSES, Permission.TRIGGER_ANALYSIS, Permission.VIEW_JOBS, Permission.ADMINISTER_SYSTEM}),
}


@dataclass(frozen=True)
class APIKeyPrincipal:
    key: str
    role: Role
    actor_id: str


@dataclass(frozen=True)
class AuthenticatedActor:
    actor_id: str
    role: Role
    auth_mode: str

    def has_permission(self, permission: Permission) -> bool:
        return permission in ROLE_PERMISSIONS[self.role]


class APIKeyAuthenticator:
    def __init__(self, config: SecurityConfig, audit_sink: Optional[AuditSink] = None) -> None:
        self.config = config
        self.audit_sink = audit_sink
        self._principals = tuple(_parse_principals(config.api_keys))

    def authenticate(self, request: Request) -> AuthenticatedActor:
        if self.config.auth_mode == "development":
            actor = AuthenticatedActor(actor_id=self.config.development_actor_id, role=_role_or_admin(self.config.development_role_name), auth_mode="development")
            self._audit(actor, "authentication", "api", AuditOutcome.SUCCESS, {"mode": "development"})
            return actor

        credential = _extract_api_key(request)
        if not credential:
            actor = AuthenticatedActor(actor_id="anonymous", role=Role.VIEWER, auth_mode=self.config.auth_mode)
            self._audit(actor, "authentication", "api", AuditOutcome.FAILURE, {"reason": "missing_api_key"})
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

        for principal in self._principals:
            if hmac.compare_digest(credential, principal.key):
                actor = AuthenticatedActor(actor_id=principal.actor_id, role=principal.role, auth_mode="api_key")
                self._audit(actor, "authentication", "api", AuditOutcome.SUCCESS, {"mode": "api_key"})
                return actor

        actor = AuthenticatedActor(actor_id="anonymous", role=Role.VIEWER, auth_mode="api_key")
        self._audit(actor, "authentication", "api", AuditOutcome.FAILURE, {"reason": "invalid_api_key"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    def _audit(self, actor: AuthenticatedActor, action: str, target: str, outcome: AuditOutcome, details: Mapping[str, object]) -> None:
        if self.audit_sink is None:
            return
        self.audit_sink.write(
            AuditEvent(
                actor_id=actor.actor_id,
                role=actor.role.value,
                action=action,
                target=target,
                outcome=outcome,
                details=details,
            )
        )


class Authorizer:
    def __init__(self, audit_sink: Optional[AuditSink] = None) -> None:
        self.audit_sink = audit_sink

    def require(self, actor: AuthenticatedActor, permission: Permission, *, target: str) -> AuthenticatedActor:
        if actor.has_permission(permission):
            return actor
        if self.audit_sink is not None:
            self.audit_sink.write(
                AuditEvent(
                    actor_id=actor.actor_id,
                    role=actor.role.value,
                    action=f"authorize:{permission.value}",
                    target=target,
                    outcome=AuditOutcome.DENIED,
                    details={"permission": permission.value},
                )
            )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


def permission_dependency(permission: Permission, *, target: str):
    def _dependency(request: Request) -> AuthenticatedActor:
        authenticator: APIKeyAuthenticator = request.app.state.authenticator
        authorizer: Authorizer = request.app.state.authorizer
        actor = authenticator.authenticate(request)
        return authorizer.require(actor, permission, target=target)

    return Depends(_dependency)


def _extract_api_key(request: Request) -> str:
    header = request.headers.get("x-api-key", "").strip()
    if header:
        return header
    authorization = request.headers.get("authorization", "").strip()
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def _parse_principals(raw_values: Iterable[str]) -> tuple[APIKeyPrincipal, ...]:
    principals: list[APIKeyPrincipal] = []
    for raw in raw_values:
        parts = [part.strip() for part in str(raw).split(":")]
        if len(parts) < 2 or not parts[0]:
            continue
        key = parts[0]
        role_value = parts[1]
        actor_id = parts[2] if len(parts) >= 3 and parts[2] else f"{role_value}-api-key"
        try:
            role = Role(role_value)
        except ValueError:
            continue
        principals.append(APIKeyPrincipal(key=key, role=role, actor_id=actor_id))
    return tuple(principals)


def _role_or_admin(value: str) -> Role:
    try:
        return Role(value)
    except ValueError:
        return Role.ADMIN
