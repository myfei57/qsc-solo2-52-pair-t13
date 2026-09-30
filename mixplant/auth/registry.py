"""The in memory fold of every authorization ticket.

The registry holds no truth of its own: it is rebuilt from the committed
record stream on boot and only mutates through named transitions.  Every
transition is a compare and set on the previous status, so two concurrent
redemptions of the same ticket can never both win.
"""

from __future__ import annotations

import threading
from dataclasses import replace
from typing import Any

from ..errors import (
    AuthorizationConsumedError,
    AuthorizationExpiredError,
    AuthorizationReuseRejectedError,
    NotFoundError,
)
from .ticket import (
    EXPIRED,
    ISSUED,
    REDEEMED,
    REOPENABLE,
    REVOKED,
    STRICT,
    TERMINAL_STATES,
    Ticket,
)

#: Record kinds, shaped '<group>.<leaf>' so the generic state reducer accepts them.
TICKET_KIND = "auth.ticket"
REDEEM_KIND = "auth.redeem"
EXPIRE_KIND = "auth.expire"
REVOKE_KIND = "auth.revoke"
REOPEN_KIND = "auth.reopen"
SWEEP_KIND = "auth.sweep"


class TicketRegistry:
    """Owns the live ticket fold and serialises every transition.

    The lock turns concurrent redemption requests into a deterministic
    sequence; the compare and set on ``status`` makes only the first
    ``ISSUED -> REDEEMED`` transition win, even within that sequence.
    """

    __slots__ = ("_tickets", "_results", "_lock")

    def __init__(self) -> None:
        self._tickets: dict[str, Ticket] = {}
        self._results: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    # ------------------------------------------------------------------ adopt

    def adopt(self, ticket: Ticket) -> None:
        """Place a ticket read back from the stream, keeping the newest copy."""

        with self._lock:
            self._tickets[ticket.ticket_id] = ticket

    def adopt_result(self, request_id: str, result: dict[str, Any]) -> None:
        """Remember the outcome of a request id so a retry replays it."""

        if request_id:
            self._results[request_id] = dict(result)

    # ------------------------------------------------------------------ reads

    def get(self, ticket_id: str) -> Ticket:
        try:
            return self._tickets[ticket_id]
        except KeyError:
            raise NotFoundError("authorization ticket does not exist", ticket_id=ticket_id) from None

    def all(self) -> tuple[Ticket, ...]:
        return tuple(self._tickets.values())

    def by_status(self, status: str) -> tuple[Ticket, ...]:
        return tuple(t for t in self._tickets.values() if t.status == status)

    def issued_for(self, action: str) -> tuple[Ticket, ...]:
        return tuple(
            t for t in self._tickets.values() if t.action == action and t.status == ISSUED
        )

    def live_for(self, action: str, *, now: int) -> tuple[Ticket, ...]:
        """Issued and non expired tickets for an action."""

        return tuple(
            t for t in self.issued_for(action) if not t.validity.is_expired(now)
        )

    def status_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {ISSUED: 0, REDEEMED: 0, EXPIRED: 0, REVOKED: 0}
        for ticket in self._tickets.values():
            counts[ticket.status] += 1
        return counts

    def describe(self, now: int) -> dict[str, Any]:
        return {
            "counts": self.status_counts(),
            "tickets": [ticket.describe(now) for ticket in self._tickets.values()],
        }

    # -------------------------------------------------------------- transitions

    def expire_if_due(self, ticket_id: str, now: int) -> Ticket | None:
        """Move one issued, past window ticket to ``EXPIRED``.

        This is the real time expiry rule: it runs inside every redemption
        and status read, so an expired ticket can never win the gate.
        """

        with self._lock:
            ticket = self.get(ticket_id)
            if ticket.status != ISSUED:
                return None
            if not ticket.validity.is_expired(now):
                return None
            expired = replace(ticket, status=EXPIRED, ended_tick=now)
            self._tickets[ticket_id] = expired
            return expired

    def sweep(self, now: int) -> tuple[Ticket, ...]:
        """Expire every issued ticket whose window has closed."""

        with self._lock:
            changed: list[Ticket] = []
            for ticket in tuple(self._tickets.values()):
                expired = self.expire_if_due(ticket.ticket_id, now)
                if expired is not None:
                    changed.append(expired)
            return tuple(changed)

    def apply_redeem(
        self,
        ticket_id: str,
        *,
        now: int,
        request_id: str | None,
        redeemed_by: str,
    ) -> Ticket:
        """Compare and set one ticket from ``ISSUED`` to ``REDEEMED``.

        Raises the typed refusal a caller can act on; never moves a terminal
        ticket, so a second presentation cannot succeed.
        """

        with self._lock:
            ticket = self.get(ticket_id)
            if ticket.status == REDEEMED:
                if ticket.reuse_policy == STRICT:
                    raise AuthorizationReuseRejectedError(
                        "the authorization was already redeemed and its type forbids reuse",
                        ticket_id=ticket_id,
                        action=ticket.action,
                        reuse_policy=STRICT,
                    )
                raise AuthorizationConsumedError(
                    "the authorization was already redeemed",
                    ticket_id=ticket_id,
                    action=ticket.action,
                    replacement_id=ticket.replacement_id,
                )
            if ticket.status == EXPIRED:
                raise AuthorizationExpiredError(
                    "the authorization expired before it was redeemed",
                    ticket_id=ticket_id,
                    valid_until=ticket.validity.valid_until(),
                    now=now,
                )
            if ticket.status == REVOKED:
                raise AuthorizationConsumedError(
                    "the authorization was revoked and cannot be redeemed",
                    ticket_id=ticket_id,
                    action=ticket.action,
                    revoke_reason=ticket.revoke_reason,
                )
            # status == ISSUED; the window is checked here, atomically with the CAS.
            if ticket.validity.is_expired(now):
                expired = replace(ticket, status=EXPIRED, ended_tick=now)
                self._tickets[ticket_id] = expired
                raise AuthorizationExpiredError(
                    "the authorization expired before it was redeemed",
                    ticket_id=ticket_id,
                    valid_until=ticket.validity.valid_until(),
                    now=now,
                )
            redeemed = replace(
                ticket,
                status=REDEEMED,
                redeemed_tick=now,
                redeemed_by=redeemed_by,
                request_id=request_id,
                ended_tick=now,
            )
            self._tickets[ticket_id] = redeemed
            return redeemed

    def apply_revoke(self, ticket_id: str, *, now: int, reason: str) -> Ticket:
        """Void a ticket; terminal tickets stay terminal and are never revived."""

        with self._lock:
            ticket = self.get(ticket_id)
            if ticket.status in TERMINAL_STATES:
                raise AuthorizationConsumedError(
                    "a terminal authorization cannot be returned or reopened",
                    ticket_id=ticket_id,
                    status=ticket.status,
                )
            revoked = replace(
                ticket, status=REVOKED, ended_tick=now, revoke_reason=reason
            )
            self._tickets[ticket_id] = revoked
            return revoked

    def link_replacement(self, old_id: str, *, replacement_id: str) -> Ticket:
        """Record that a revoked ticket was superseded by a fresh one."""

        with self._lock:
            ticket = self.get(old_id)
            linked = replace(ticket, replacement_id=replacement_id)
            self._tickets[old_id] = linked
            return linked

    def replay_result(self, request_id: str) -> dict[str, Any] | None:
        return self._results.get(request_id)
