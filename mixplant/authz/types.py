"""Shared authorization terminology."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from ..errors import ValidationError


class AuthorizationType(StrEnum):
    """The two slip kinds the gate accepts."""

    WAREHOUSE_OPEN = "warehouse_open"
    GATE_RELEASE = "gate_release"


class AuthorizationStatus(StrEnum):
    """Lifecycle states for a single authorization revision."""

    ACTIVE = "active"
    REDEEMED = "redeemed"
    RETURNED = "returned"
    VOIDED = "voided"
    EXPIRED = "expired"


class ReusePolicy(StrEnum):
    """What happens when a slip is presented after it was consumed."""

    REJECT = "reject"
    VOID_AND_REOPEN = "void_and_reopen"


TYPE_REUSE_POLICIES: dict[AuthorizationType, ReusePolicy] = {
    AuthorizationType.WAREHOUSE_OPEN: ReusePolicy.REJECT,
    AuthorizationType.GATE_RELEASE: ReusePolicy.VOID_AND_REOPEN,
}

TERMINAL_STATUSES = frozenset(
    {
        AuthorizationStatus.REDEEMED,
        AuthorizationStatus.RETURNED,
        AuthorizationStatus.VOIDED,
        AuthorizationStatus.EXPIRED,
    }
)


@dataclass(frozen=True, slots=True)
class Authorization:
    """One immutable revision of an authorization slip."""

    auth_id: str
    ticket_no: str
    auth_type: AuthorizationType
    status: AuthorizationStatus
    issued_tick: int
    expires_at: int
    redeemed_tick: int | None = None
    action: str | None = None
    request_id: str | None = None
    replacement_for: str | None = None
    replaced_by: str | None = None

    @property
    def reuse_policy(self) -> ReusePolicy:
        return TYPE_REUSE_POLICIES[self.auth_type]

    def is_valid(self, now: int) -> bool:
        return self.status is AuthorizationStatus.ACTIVE and now < self.expires_at

    def with_status(
        self,
        status: AuthorizationStatus,
        *,
        tick: int,
        action: str | None = None,
        request_id: str | None = None,
        replaced_by: str | None = None,
    ) -> "Authorization":
        return Authorization(
            auth_id=self.auth_id,
            ticket_no=self.ticket_no,
            auth_type=self.auth_type,
            status=status,
            issued_tick=self.issued_tick,
            expires_at=self.expires_at,
            redeemed_tick=tick if status is AuthorizationStatus.REDEEMED else self.redeemed_tick,
            action=action or self.action,
            request_id=request_id or self.request_id,
            replacement_for=self.replacement_for,
            replaced_by=replaced_by or self.replaced_by,
        )

    def describe(self, now: int | None = None) -> dict[str, Any]:
        document = {
            "active": self.status is AuthorizationStatus.ACTIVE,
            "auth_id": self.auth_id,
            "ticket_no": self.ticket_no,
            "type": self.auth_type.value,
            "status": self.status.value,
            "reuse_policy": self.reuse_policy.value,
            "issued_tick": self.issued_tick,
            "expires_at": self.expires_at,
            "redeemed_tick": self.redeemed_tick,
            "action": self.action,
            "request_id": self.request_id,
            "replacement_for": self.replacement_for,
            "replaced_by": self.replaced_by,
        }
        if now is not None:
            document["valid"] = self.is_valid(now)
        return document


def authorization_type(value: str | AuthorizationType) -> AuthorizationType:
    """Validate and normalize an authorization type."""

    try:
        return AuthorizationType(str(value))
    except ValueError as exc:
        valid = sorted(item.value for item in AuthorizationType)
        raise ValidationError("unknown authorization type", value=str(value), valid=valid) from exc


def authorization_from_payload(payload: Mapping[str, Any]) -> Authorization:
    """Rebuild an authorization revision from its stored payload."""

    redeemed = payload.get("redeemed_tick")
    action = payload.get("action")
    request_id = payload.get("request_id")
    replacement_for = payload.get("replacement_for")
    replaced_by = payload.get("replaced_by")
    return Authorization(
        auth_id=str(payload["auth_id"]),
        ticket_no=str(payload["ticket_no"]),
        auth_type=authorization_type(str(payload["type"])),
        status=AuthorizationStatus(str(payload["status"])),
        issued_tick=int(payload["issued_tick"]),
        expires_at=int(payload["expires_at"]),
        redeemed_tick=None if redeemed is None else int(redeemed),
        action=None if action is None else str(action),
        request_id=None if request_id is None else str(request_id),
        replacement_for=None if replacement_for is None else str(replacement_for),
        replaced_by=None if replaced_by is None else str(replaced_by),
    )


def action_for_type(auth_type: AuthorizationType) -> str:
    """Return the physical action permitted by an authorization type."""

    if auth_type is AuthorizationType.WAREHOUSE_OPEN:
        return "warehouse.open"
    return "gate.release"
