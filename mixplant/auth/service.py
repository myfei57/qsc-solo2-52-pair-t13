"""The authorization service.

It is the single writer for ticket state.  Every state change is a compare
and set on the registry, committed to the record stream and announced on the
bus while holding one lock, so the ticket status, the gate action and the
audit ledger can never describe three different outcomes.

Expiry policy (fixed on purpose, not configurable per call):
real time expiry is the rule and the sweep is only the clean up pass.  A
ticket is judged against the current tick the instant it is presented, so an
expired ticket can never open a gate.  Advancing the clock runs the sweep in
the same tick, which moves every window closed ticket to ``EXPIRED`` for the
console and the audit log; safety never depends on that sweep having run.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from ..errors import (
    AuthorizationConsumedError,
    AuthorizationExpiredError,
    AuthorizationReuseRejectedError,
    NotFoundError,
    ValidationError,
)
from ..service_base import PlantService
from ..versioning.expiry import Validity
from .registry import (
    EXPIRE_KIND,
    REDEEM_KIND,
    REOPEN_KIND,
    REVOKE_KIND,
    SWEEP_KIND,
    TICKET_KIND,
    TicketRegistry,
)
from .ticket import (
    EXPIRED,
    ISSUED,
    REDEEMED,
    REOPENABLE,
    REVOKED,
    STRICT,
    Ticket,
)

GateAction = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class AuthService(PlantService):
    """Issues, redeems, expires, revokes and reopens authorization tickets."""

    origin = "auth"
    line = "batch"
    subject = "auth"

    def __init__(self, context, machine=None, *, registry: TicketRegistry | None = None) -> None:
        super().__init__(context, machine)
        self.tickets = registry or TicketRegistry()
        self._gates: dict[str, GateAction] = {}

    def register_gate(self, action: str, gate: GateAction) -> None:
        """Bind the gated command that a redeemed ticket for ``action`` runs."""

        self._gates[action] = gate

    # ------------------------------------------------------------------ issue

    def issue(
        self,
        action: str,
        *,
        reuse_policy: str = STRICT,
        ttl_ticks: int | None = None,
        issuer: str = "console",
    ) -> dict[str, Any]:
        """Hand out one single use ticket for ``action``."""

        if not action:
            raise ValidationError("an authorization needs an action")
        if reuse_policy not in (STRICT, REOPENABLE):
            raise ValidationError("unknown reuse policy", reuse_policy=reuse_policy)
        ttl = self.context.config.defaults.authorization_ttl_ticks if ttl_ticks is None else ttl_ticks
        now = self.context.clock.now()
        ticket = Ticket(
            ticket_id=self.context.ids.next("auth"),
            action=action,
            reuse_policy=reuse_policy,
            issuer=issuer,
            validity=Validity.of(now, ttl),
        )
        with self.tickets.lock:
            self.tickets.adopt(ticket)
            self.publish(TICKET_KIND, {"active": True, **ticket.to_document()})
        self.emit("auth.ticket_issued", {"ticket_id": ticket.ticket_id, "action": action})
        return {"ticket": ticket.describe(now)}

    # ----------------------------------------------------------------- redeem

    def redeem(
        self,
        ticket_id: str,
        *,
        request_id: str | None = None,
        gate_payload: Mapping[str, Any] | None = None,
        by: str = "console",
    ) -> dict[str, Any]:
        """Consume one ticket and, on the same decision, open its gate.

        Concurrent redemptions of the same ticket are serialised and
        idempotent: the first compare and set wins and the losing call gets
        the typed refusal for the ticket's reuse policy.  A retry carrying the
        same ``request_id`` replays the first outcome without reopening the
        gate.
        """

        if not ticket_id:
            raise ValidationError("redeem needs a ticket_id")
        now = self.context.clock.now()
        with self.tickets.lock:
            if request_id:
                replay = self.tickets.replay_result(request_id)
                if replay is not None:
                    return {"ticket_id": ticket_id, "idempotent": True, **replay}

            ticket = self._require(ticket_id)
            # Real time expiry: judge on the spot and clear the ticket now.
            if ticket.status == ISSUED and ticket.validity.is_expired(now):
                self._commit_expire(ticket)
                raise AuthorizationExpiredError(
                    "the authorization expired before it was redeemed",
                    ticket_id=ticket_id,
                    valid_until=ticket.validity.valid_until(),
                    now=now,
                )

            try:
                redeemed = self.tickets.apply_redeem(
                    ticket_id, now=now, request_id=request_id, redeemed_by=by
                )
            except AuthorizationReuseRejectedError:
                # A strict ticket presented twice is refused and audited, but
                # no state changes: the ticket stays REDEEMED.
                self.raise_alarm(
                    "auth.reuse_rejected",
                    {"ticket_id": ticket_id, "action": ticket.action, "reuse_policy": STRICT},
                )
                raise

            record = self.publish(
                REDEEM_KIND,
                {
                    "active": True,
                    "ticket_id": ticket_id,
                    "action": redeemed.action,
                    "request_id": request_id,
                    "by": by,
                    "tick": now,
                },
            )
            self.emit(
                "auth.ticket_redeemed",
                {"ticket_id": ticket_id, "action": redeemed.action, "request_id": request_id},
            )

            gate = self._gates.get(redeemed.action)
            gate_result: Mapping[str, Any] = {}
            if gate is not None:
                gate_result = gate(gate_payload or {})
            result = {
                "redeemed": redeemed.describe(now),
                "action": redeemed.action,
                "gate": dict(gate_result),
                "seq": record.seq,
            }
            if request_id:
                self.tickets.adopt_result(request_id, result)
            return result

    # ----------------------------------------------------------------- revoke

    def revoke(self, ticket_id: str, *, reason: str = "returned") -> dict[str, Any]:
        """Void a ticket (a returned slip).  Terminal tickets never come back."""

        now = self.context.clock.now()
        with self.tickets.lock:
            revoked = self.tickets.apply_revoke(ticket_id, now=now, reason=reason)
            self.publish(
                REVOKE_KIND,
                {"active": True, "ticket_id": ticket_id, "reason": reason, "tick": now},
            )
        self.emit("auth.ticket_revoked", {"ticket_id": ticket_id, "reason": reason})
        return {"ticket": revoked.describe(now)}

    # ----------------------------------------------------------------- reopen

    def reopen(
        self,
        ticket_id: str,
        *,
        ttl_ticks: int | None = None,
        reason: str = "void and reopen",
    ) -> dict[str, Any]:
        """Void one ticket and hand out a fresh replacement for the same action.

        Only ``reopenable`` tickets support this.  The old id is never made
        usable again: it is revoked if it was still issued and stays terminal
        otherwise, while the replacement gets a brand new id.
        """

        now = self.context.clock.now()
        with self.tickets.lock:
            old = self._require(ticket_id)
            if old.reuse_policy != REOPENABLE:
                self.raise_alarm(
                    "auth.reopen_rejected",
                    {"ticket_id": ticket_id, "action": old.action, "reuse_policy": old.reuse_policy},
                )
                raise AuthorizationReuseRejectedError(
                    "the authorization type forbids reopening; reuse is refused",
                    ticket_id=ticket_id,
                    action=old.action,
                    reuse_policy=old.reuse_policy,
                )
            if old.status == ISSUED:
                old = self.tickets.apply_revoke(ticket_id, now=now, reason=reason)
                self.publish(
                    REVOKE_KIND,
                    {"active": True, "ticket_id": ticket_id, "reason": reason, "tick": now},
                )

            ttl = self.context.config.defaults.authorization_ttl_ticks if ttl_ticks is None else ttl_ticks
            replacement = Ticket(
                ticket_id=self.context.ids.next("auth"),
                action=old.action,
                reuse_policy=REOPENABLE,
                issuer=old.issuer,
                validity=Validity.of(now, ttl),
            )
            self.tickets.adopt(replacement)
            self.tickets.link_replacement(ticket_id, replacement_id=replacement.ticket_id)
            self.publish(TICKET_KIND, {"active": True, **replacement.to_document()})
            # The link is the authority for the old->new chain; it is written
            # exactly once, regardless of how the old ticket reached its end.
            self.publish(
                REOPEN_KIND,
                {
                    "active": True,
                    "ticket_id": ticket_id,
                    "replacement_id": replacement.ticket_id,
                    "prior_status": old.status,
                    "reason": reason,
                    "tick": now,
                },
            )
        self.emit(
            "auth.ticket_reopened",
            {"old_ticket_id": ticket_id, "ticket_id": replacement.ticket_id, "action": old.action},
        )
        return {"ticket": replacement.describe(now), "replaced": ticket_id}

    # ----------------------------------------------------------------- expiry

    def expire_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        """Move one past window ticket to ``EXPIRED`` if it is due."""

        now = self.context.clock.now()
        with self.tickets.lock:
            ticket = self._require(ticket_id)
            if ticket.status != ISSUED or not ticket.validity.is_expired(now):
                return None
            expired = self._commit_expire(ticket)
        return {"ticket": expired.describe(now)}

    def sweep(self) -> dict[str, Any]:
        """Expire every issued ticket whose window has closed (the clean up pass)."""

        now = self.context.clock.now()
        with self.tickets.lock:
            changed = self.tickets.sweep(now)
            for expired in changed:
                self.publish(
                    EXPIRE_KIND,
                    {"active": True, "ticket_id": expired.ticket_id, "tick": now},
                )
            if changed:
                self.publish(
                    SWEEP_KIND,
                    {
                        "active": True,
                        "expired": [ticket.ticket_id for ticket in changed],
                        "tick": now,
                    },
                )
        for expired in changed:
            self.emit("auth.ticket_expired", {"ticket_id": expired.ticket_id})
        return {"expired": [ticket.ticket_id for ticket in changed], "count": len(changed)}

    # ------------------------------------------------------------------ reads

    def _require(self, ticket_id: str) -> Ticket:
        return self.tickets.get(ticket_id)

    def _commit_expire(self, ticket: Ticket) -> Ticket:
        """Persist one expiry transition; caller holds the registry lock."""

        now = self.context.clock.now()
        expired = self.tickets.expire_if_due(ticket.ticket_id, now)
        if expired is None:
            expired = self.tickets.get(ticket.ticket_id)
        self.publish(
            EXPIRE_KIND,
            {"active": True, "ticket_id": ticket.ticket_id, "tick": now},
        )
        self.emit("auth.ticket_expired", {"ticket_id": ticket.ticket_id})
        return expired

    def describe(self, now: int | None = None) -> dict[str, Any]:
        """Console snapshot; expiry is computed against the current tick."""

        tick = self.context.clock.now() if now is None else now
        with self.tickets.lock:
            # Keep the live fold honest for a reader that never sweeps.
            due = [t for t in self.tickets.by_status(ISSUED) if t.validity.is_expired(tick)]
            return {
                "counts": self.tickets.status_counts(),
                "due_for_expiry": [t.ticket_id for t in due],
                "tickets": [ticket.describe(tick) for ticket in self.tickets.all()],
            }

    def status(self) -> dict[str, Any]:
        return self.describe()

    # ----------------------------------------------------------------- replay

    def adopt_issued(self, document: Mapping[str, Any]) -> Ticket:
        """Rebuild one ticket from an ``auth.ticket`` record on restart."""

        ticket = Ticket.from_document(document)
        self.tickets.adopt(ticket)
        return ticket

    def adopt_redeemed(
        self,
        ticket_id: str,
        *,
        request_id: str | None,
        result: Mapping[str, Any] | None = None,
    ) -> None:
        """Mark a ticket redeemed while replaying the stream after a restart.

        Idempotent: replay must fold a stream that may already carry the
        ticket in its terminal fold.
        """

        now = self.context.clock.now()
        ticket = self.tickets.get(ticket_id)
        if ticket.status == REDEEMED:
            redeemed = ticket
        else:
            redeemed = self.tickets.apply_redeem(
                ticket_id, now=now, request_id=request_id, redeemed_by="replay"
            )
        if request_id:
            self.tickets.adopt_result(
                request_id,
                dict(result)
                if result is not None
                else {"redeemed": redeemed.describe(now), "action": redeemed.action, "gate": {}, "replayed": True},
            )

    def adopt_expired(self, ticket_id: str) -> None:
        from dataclasses import replace

        ticket = self.tickets.get(ticket_id)
        if ticket.status != EXPIRED:
            self.tickets.adopt(
                replace(ticket, status=EXPIRED, ended_tick=self.context.clock.now())
            )

    def adopt_revoked(self, ticket_id: str, *, reason: str | None = None) -> None:
        ticket = self.tickets.get(ticket_id)
        if ticket.status == REVOKED:
            return
        self.tickets.apply_revoke(
            ticket_id, now=self.context.clock.now(), reason=reason or "replayed"
        )

    def gate_actions(self) -> tuple[str, ...]:
        return tuple(sorted(self._gates))
