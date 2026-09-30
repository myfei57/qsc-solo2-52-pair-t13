"""Single use authorization tickets for gated plant actions.

A ticket is the only thing that lets a gated action (open silo, discharge
door, start pump ...) run.  It is born ``ISSUED`` and ends in exactly one
terminal state.  Terminal states never move, so a ticket that was redeemed,
revoked or expired can never be handed to a gate a second time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..errors import ValidationError
from ..versioning.expiry import Validity

ISSUED = "issued"
REDEEMED = "redeemed"
EXPIRED = "expired"
REVOKED = "revoked"

TERMINAL_STATES = frozenset({REDEEMED, EXPIRED, REVOKED})

#: A strict ticket may be presented once; a second presentation is refused.
STRICT = "strict"
#: A reopenable ticket may be voided and replaced, but the old id never revives.
REOPENABLE = "reopenable"

REUSE_POLICIES = frozenset({STRICT, REOPENABLE})


@dataclass(frozen=True, slots=True)
class Ticket:
    """One authorization issued for one action."""

    ticket_id: str
    action: str
    reuse_policy: str
    validity: Validity
    issuer: str
    status: str = ISSUED
    redeemed_tick: int | None = None
    redeemed_by: str | None = None
    request_id: str | None = None
    ended_tick: int | None = None
    replacement_id: str | None = None
    revoke_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.ticket_id:
            raise ValidationError("a ticket needs an id")
        if not self.action:
            raise ValidationError("a ticket needs an action")
        if self.reuse_policy not in REUSE_POLICIES:
            raise ValidationError("unknown reuse policy", reuse_policy=self.reuse_policy)
        if self.status not in {ISSUED, *TERMINAL_STATES}:
            raise ValidationError("unknown ticket status", status=self.status)

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STATES

    def is_expired(self, now: int) -> bool:
        """An issued ticket whose window has closed; terminal tickets stay put."""

        return self.status == ISSUED and self.validity.is_expired(now)

    def describe(self, now: int | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {
            "ticket_id": self.ticket_id,
            "action": self.action,
            "reuse_policy": self.reuse_policy,
            "issuer": self.issuer,
            "status": self.status,
            "terminal": self.terminal,
            "validity": self.validity.describe(now),
            "redeemed_tick": self.redeemed_tick,
            "redeemed_by": self.redeemed_by,
            "request_id": self.request_id,
            "ended_tick": self.ended_tick,
            "replacement_id": self.replacement_id,
            "revoke_reason": self.revoke_reason,
        }
        return body

    def to_document(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "action": self.action,
            "reuse_policy": self.reuse_policy,
            "issuer": self.issuer,
            "status": self.status,
            "validity": self.validity.to_document(),
            "redeemed_tick": self.redeemed_tick,
            "redeemed_by": self.redeemed_by,
            "request_id": self.request_id,
            "ended_tick": self.ended_tick,
            "replacement_id": self.replacement_id,
            "revoke_reason": self.revoke_reason,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "Ticket":
        def optional_str(key: str) -> str | None:
            value = document.get(key)
            return None if value is None else str(value)

        return cls(
            ticket_id=str(document["ticket_id"]),
            action=str(document["action"]),
            reuse_policy=str(document.get("reuse_policy", STRICT)),
            issuer=str(document.get("issuer", "console")),
            status=str(document.get("status", ISSUED)),
            validity=Validity.from_document(document["validity"]),
            redeemed_tick=None
            if document.get("redeemed_tick") is None
            else int(document["redeemed_tick"]),
            redeemed_by=optional_str("redeemed_by"),
            request_id=optional_str("request_id"),
            ended_tick=None if document.get("ended_tick") is None else int(document["ended_tick"]),
            replacement_id=optional_str("replacement_id"),
            revoke_reason=optional_str("revoke_reason"),
        )
