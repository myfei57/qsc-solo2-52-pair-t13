"""Issue, consume, return and expire one-time authorizations."""

from __future__ import annotations

import threading
from typing import Any

from ..audit.audit import ENTRY_KIND
from ..audit.record import audit_entry
from ..errors import AuthorizationError, ValidationError
from ..service_base import PlantService
from .registry import AuthorizationRegistry
from .types import (
    TERMINAL_STATUSES,
    Authorization,
    AuthorizationStatus,
    AuthorizationType,
    ReusePolicy,
    action_for_type,
    authorization_from_payload,
    authorization_type,
)

AUTHORIZATION_KIND = "authz.authorization"
ACTION_KIND = "authz.action"
EXPIRY_POLICY = "realtime_on_access"


class AuthorizationService(PlantService):
    """Authorizations are one-time tokens with type-specific replay policy."""

    origin = "authz"
    line = "batch"
    subject = "authz"

    def __init__(self, context) -> None:
        super().__init__(context)
        self.registry = AuthorizationRegistry()
        self._lock = threading.RLock()

    def issue(
        self,
        *,
        ticket_no: str,
        auth_type: str | AuthorizationType,
        ttl_ticks: int | None = None,
    ) -> dict[str, Any]:
        """Issue a fresh, active authorization revision."""

        ticket_no = self._ticket(ticket_no)
        kind = authorization_type(auth_type)
        ttl = self._ttl(ttl_ticks)
        with self._lock:
            expired = self.sweep_expired()
            existing = self.registry.find_ticket(ticket_no)
            if existing is not None:
                raise AuthorizationError(
                    "a finished or active authorization cannot be reissued; issue a fresh ticket",
                    ticket_no=ticket_no,
                    status=existing.status.value,
                )

            now = self.context.clock.now()
            authorization = self._new_authorization(
                ticket_no=ticket_no,
                auth_type=kind,
                now=now,
                ttl_ticks=ttl,
            )
            entries = [*expired.entries]
            entries.extend(
                self._issue_entries(authorization),
            )
            records = self._commit(entries)
            for item in [*(expired.authorizations), authorization]:
                self.registry.adopt(item)
            return self._issue_result(authorization, records, expired=expired)

    def redeem(self, *, ticket_no: str, request_id: str | None = None) -> dict[str, Any]:
        """Consume an authorization once and record the permitted gate action."""

        ticket_no = self._ticket(ticket_no)
        request_id = self._request_id(request_id)
        with self._lock:
            expired = self.sweep_expired()
            if request_id is not None:
                consumed = self.registry.find_request(request_id)
                if consumed is not None:
                    if consumed.ticket_no != ticket_no:
                        raise AuthorizationError(
                            "request_id was already used for another ticket",
                            request_id=request_id,
                            ticket_no=ticket_no,
                            consumed_ticket_no=consumed.ticket_no,
                        )
                    return self._redeem_result(
                        consumed,
                        consumed,
                        action_seq=self.action_seq(consumed, request_id),
                        expired=expired,
                        idempotent=True,
                    )
            authorization = self.registry.require_ticket(ticket_no)

            if authorization.status is not AuthorizationStatus.ACTIVE:
                if authorization.reuse_policy is ReusePolicy.REJECT:
                    raise AuthorizationError(
                        "this authorization type does not permit reopening",
                        ticket_no=ticket_no,
                        status=authorization.status.value,
                        policy=authorization.reuse_policy.value,
                    )
                return self._redeem_with_replacement(authorization, request_id, expired)

            return self._redeem_active(authorization, request_id, expired)

    def return_authorization(
        self,
        *,
        auth_id: str | None = None,
        ticket_no: str | None = None,
    ) -> dict[str, Any]:
        """Return an unused authorization; a returned slip cannot be redeemed."""

        return self._finish(
            self._locate(auth_id, ticket_no),
            AuthorizationStatus.RETURNED,
            "authorization returned",
        )

    def void(
        self,
        *,
        auth_id: str | None = None,
        ticket_no: str | None = None,
        reason: str = "authorization voided",
    ) -> dict[str, Any]:
        """Administratively void an authorization revision."""

        return self._finish(self._locate(auth_id, ticket_no), AuthorizationStatus.VOIDED, reason)

    def get(self, *, auth_id: str | None = None, ticket_no: str | None = None) -> dict[str, Any]:
        """Return one authorization revision for the console."""

        with self._lock:
            self.sweep_expired()
            return self._locate(auth_id, ticket_no).describe(self.context.clock.now())

    def audit_trail(
        self,
        *,
        auth_id: str | None = None,
        ticket_no: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return journal audit entries tied to one authorization or ticket."""

        authorization = self._locate(auth_id, ticket_no)
        entries = []
        for record in self.store.committed_records():
            if record.kind != ENTRY_KIND:
                continue
            detail = record.payload.get("detail")
            if not isinstance(detail, dict):
                continue
            if (
                detail.get("auth_id") == authorization.auth_id
                or detail.get("ticket_no") == authorization.ticket_no
            ):
                entries.append(dict(record.payload))
        return entries

    def sweep_expired(self) -> "ExpiryBatch":
        """Atomically mark every active authorization whose deadline has passed."""

        now = self.context.clock.now()
        expiring = tuple(
            item.with_status(AuthorizationStatus.EXPIRED, tick=now)
            for item in self.registry.all()
            if item.status is AuthorizationStatus.ACTIVE and now >= item.expires_at
        )
        entries: list[tuple[str, str, int, dict[str, Any]]] = []
        for authorization in expiring:
            entries.extend(self._status_entries(authorization, "authorization.expired"))
        records = self._commit(entries) if entries else ()
        for authorization in expiring:
            self.registry.adopt(authorization)
        return ExpiryBatch(authorizations=expiring, entries=entries, records=records)

    def restore(self) -> None:
        """Rebuild the in-memory registry from the committed journal."""

        registry = AuthorizationRegistry()
        for record in self.store.history(AUTHORIZATION_KIND):
            registry.adopt(authorization_from_payload(dict(record.payload)))
        self.registry = registry

    def action_seq(self, authorization: Authorization, request_id: str | None) -> int:
        """Return the committed action sequence for a redemption request."""

        expected_request = request_id or authorization.request_id
        for record in self.store.history(ACTION_KIND):
            if (
                record.payload.get("auth_id") == authorization.auth_id
                and record.payload.get("request_id") == expected_request
            ):
                return record.seq
        return 0

    def status(self) -> dict[str, Any]:
        with self._lock:
            expired = self.sweep_expired()
        now = self.context.clock.now()
        view = self.registry.describe(now)
        view["expiry_policy"] = EXPIRY_POLICY
        view["expired_this_access"] = [item.describe(now) for item in expired.authorizations]
        return view

    def _redeem_active(
        self,
        authorization: Authorization,
        request_id: str | None,
        expired: ExpiryBatch,
    ):
        now = self.context.clock.now()
        redeemed = authorization.with_status(
            AuthorizationStatus.REDEEMED,
            tick=now,
            action=action_for_type(authorization.auth_type),
            request_id=request_id,
        )
        entries = [*expired.entries]
        entries.extend(
            self._redemption_entries(
                redeemed,
                request_id=request_id,
                audit_name="authorization.redeemed",
                action_seq_placeholder=True,
            )
        )
        records = self._commit(entries)
        self.registry.adopt(redeemed)
        action_seq = records[-2].seq
        return self._redeem_result(redeemed, redeemed, action_seq=action_seq, expired=expired)

    def _redeem_with_replacement(
        self,
        authorization: Authorization,
        request_id: str | None,
        expired: ExpiryBatch,
    ):
        if authorization.status is AuthorizationStatus.EXPIRED:
            raise AuthorizationError(
                "authorization has expired",
                ticket_no=authorization.ticket_no,
                status=authorization.status.value,
            )
        now = self.context.clock.now()
        replacement = self._new_authorization(
            ticket_no=authorization.ticket_no,
            auth_type=authorization.auth_type,
            now=now,
            ttl_ticks=max(1, authorization.expires_at - authorization.issued_tick),
            replacement_for=authorization.auth_id,
        )
        reopened = authorization.with_status(
            AuthorizationStatus.VOIDED,
            tick=now,
            replaced_by=replacement.auth_id,
        )
        redeemed = replacement.with_status(
            AuthorizationStatus.REDEEMED,
            tick=now,
            action=action_for_type(replacement.auth_type),
            request_id=request_id,
        )
        entries = [*expired.entries]
        entries.extend(self._status_entries(reopened, "authorization.reuse_voided"))
        entries.extend(
            self._issue_entries(
                replacement,
                audit_name="authorization.reopened",
                action_placeholder=False,
            )
        )
        entries.extend(
            self._redemption_entries(
                redeemed,
                request_id=request_id,
                audit_name="authorization.redeemed",
                action_seq_placeholder=True,
                replaced_revision=authorization.auth_id,
            )
        )
        records = self._commit(entries)
        self.registry.adopt(reopened)
        self.registry.adopt(redeemed)
        action_seq = records[-2].seq
        return self._redeem_result(
            redeemed,
            reopened,
            action_seq=action_seq,
            expired=expired,
            replacement=redeemed,
        )

    def _finish(
        self,
        authorization: Authorization,
        status: AuthorizationStatus,
        reason: str,
    ) -> dict[str, Any]:
        if authorization.status in TERMINAL_STATUSES:
            raise AuthorizationError(
                "authorization is already finished",
                auth_id=authorization.auth_id,
                status=authorization.status.value,
            )
        with self._lock:
            expired = self.sweep_expired()
            authorization = self.registry.get(authorization.auth_id)
            if authorization.status in TERMINAL_STATUSES:
                raise AuthorizationError(
                    "authorization is already finished",
                    auth_id=authorization.auth_id,
                    status=authorization.status.value,
                )
            now = self.context.clock.now()
            finished = authorization.with_status(status, tick=now)
            entries = [*expired.entries, *self._status_entries(finished, reason)]
            records = self._commit(entries)
            self.registry.adopt(finished)
            return {
                "authorization": finished.describe(now),
                "seq": records[-1].seq if records else None,
                "expired": [item.describe(now) for item in expired.authorizations],
            }

    def _locate(self, auth_id: str | None, ticket_no: str | None) -> Authorization:
        if auth_id and ticket_no:
            authorization = self.registry.get(auth_id)
            if authorization.ticket_no != ticket_no:
                raise AuthorizationError(
                    "authorization and ticket do not match",
                    auth_id=auth_id,
                    ticket_no=ticket_no,
                )
            return authorization
        if auth_id:
            return self.registry.get(auth_id)
        if ticket_no:
            return self.registry.require_ticket(self._ticket(ticket_no))
        raise ValidationError("auth_id or ticket_no is required")

    def _new_authorization(
        self,
        *,
        ticket_no: str,
        auth_type: AuthorizationType,
        now: int,
        ttl_ticks: int,
        replacement_for: str | None = None,
    ) -> Authorization:
        return Authorization(
            auth_id=self.context.ids.next("auth"),
            ticket_no=ticket_no,
            auth_type=auth_type,
            status=AuthorizationStatus.ACTIVE,
            issued_tick=now,
            expires_at=now + ttl_ticks,
            replacement_for=replacement_for,
        )

    def _issue_entries(
        self,
        authorization: Authorization,
        *,
        audit_name: str = "authorization.issued",
        action_placeholder: bool = False,
    ) -> list[tuple[str, str, int, dict[str, Any]]]:
        del action_placeholder
        return [
            (AUTHORIZATION_KIND, self.origin, self.generation(), authorization.describe()),
            (
                ENTRY_KIND,
                self.origin,
                self.generation(),
                self._audit_payload(
                    audit_name,
                    authorization,
                    detail={
                        "reuse_policy": authorization.reuse_policy.value,
                        "expires_at": authorization.expires_at,
                    },
                ),
            ),
        ]

    def _status_entries(self, authorization: Authorization, audit_name: str):
        return [
            (AUTHORIZATION_KIND, self.origin, self.generation(), authorization.describe()),
            (
                ENTRY_KIND,
                self.origin,
                self.generation(),
                self._audit_payload(
                    audit_name,
                    authorization,
                    detail={"status": authorization.status.value},
                ),
            ),
        ]

    def _redemption_entries(
        self,
        authorization: Authorization,
        *,
        request_id: str | None,
        audit_name: str,
        action_seq_placeholder: bool,
        replaced_revision: str | None = None,
    ):
        del action_seq_placeholder
        detail = {
            "action": authorization.action,
            "request_id": request_id,
            "status": AuthorizationStatus.REDEEMED.value,
        }
        if replaced_revision is not None:
            detail["replaced_revision"] = replaced_revision
        return [
            (AUTHORIZATION_KIND, self.origin, self.generation(), authorization.describe()),
            (
                ACTION_KIND,
                self.origin,
                self.generation(),
                {
                    "active": True,
                    "auth_id": authorization.auth_id,
                    "ticket_no": authorization.ticket_no,
                    "type": authorization.auth_type.value,
                    "action": authorization.action,
                    "request_id": request_id,
                    "tick": self.context.clock.now(),
                },
            ),
            (
                ENTRY_KIND,
                self.origin,
                self.generation(),
                self._audit_payload(audit_name, authorization, detail=detail),
            ),
        ]

    def _audit_payload(
        self,
        name: str,
        authorization: Authorization,
        *,
        detail: dict[str, Any],
    ) -> dict[str, Any]:
        full_detail = {
            "auth_id": authorization.auth_id,
            "ticket_no": authorization.ticket_no,
            "type": authorization.auth_type.value,
            **detail,
        }
        entry = audit_entry(
            name=name,
            origin=self.origin,
            tick=self.context.clock.now(),
            detail=full_detail,
        )
        return entry.describe()

    def _commit(self, entries):
        return self.store.publish_all(entries) if entries else ()

    def _issue_result(self, authorization, records, *, expired: "ExpiryBatch") -> dict[str, Any]:
        now = self.context.clock.now()
        return {
            "authorization": authorization.describe(now),
            "seq": records[-1].seq,
            "expired": [item.describe(now) for item in expired.authorizations],
        }

    def _redeem_result(
        self,
        redeemed: Authorization,
        previous: Authorization,
        *,
        action_seq: int,
        expired: "ExpiryBatch",
        idempotent: bool = False,
        replacement: Authorization | None = None,
    ) -> dict[str, Any]:
        now = self.context.clock.now()
        return {
            "authorization": redeemed.describe(now),
            "previous": previous.describe(now),
            "action": redeemed.action,
            "action_seq": action_seq,
            "idempotent": idempotent,
            "replacement": None if replacement is None else replacement.describe(now),
            "expired": [item.describe(now) for item in expired.authorizations],
        }

    @staticmethod
    def _ticket(value: Any) -> str:
        if value is None or str(value).strip() == "":
            raise ValidationError("ticket_no is required")
        return str(value).strip()

    @staticmethod
    def _request_id(value: Any) -> str:
        value = AuthorizationService._optional_text(value, "request_id")
        if value is None:
            raise ValidationError("request_id is required for idempotent redemption")
        return value

    @staticmethod
    def _optional_text(value: Any, field_name: str) -> str | None:
        if value is None or str(value).strip() == "":
            return None
        return str(value).strip()

    def _ttl(self, ttl_ticks: int | None) -> int:
        default_ttl = self.context.config.defaults.authorization_ttl_ticks
        ttl = default_ttl if ttl_ticks is None else int(ttl_ticks)
        if ttl <= 0:
            raise ValidationError("authorization ttl must be positive", ttl_ticks=ttl)
        return ttl


class ExpiryBatch:
    """Records and domain objects produced by one real-time expiry sweep."""

    __slots__ = ("authorizations", "entries", "records")

    def __init__(self, *, authorizations, entries, records) -> None:
        self.authorizations = authorizations
        self.entries = entries
        self.records = records
