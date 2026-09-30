"""In-memory indexes for authorization revisions."""

from __future__ import annotations

from ..errors import NotFoundError
from .types import Authorization


class AuthorizationRegistry:
    """Keeps the latest revision of every authorization and ticket."""

    __slots__ = ("_by_id", "_ticket_latest", "_request_index")

    def __init__(self) -> None:
        self._by_id: dict[str, Authorization] = {}
        self._ticket_latest: dict[str, str] = {}
        self._request_index: dict[str, str] = {}

    def adopt(self, authorization: Authorization) -> None:
        """Upsert a revision read from the journal."""

        current = self._by_id.get(authorization.auth_id)
        if current is not None and current.issued_tick > authorization.issued_tick:
            return
        self._by_id[authorization.auth_id] = authorization
        latest_id = self._ticket_latest.get(authorization.ticket_no)
        latest = self._by_id.get(latest_id) if latest_id is not None else None
        if latest is None or authorization.issued_tick >= latest.issued_tick:
            self._ticket_latest[authorization.ticket_no] = authorization.auth_id
        if authorization.request_id:
            self._request_index[authorization.request_id] = authorization.auth_id

    def get(self, auth_id: str) -> Authorization:
        try:
            return self._by_id[auth_id]
        except KeyError as exc:
            raise NotFoundError("authorization does not exist", auth_id=auth_id) from exc

    def find_ticket(self, ticket_no: str) -> Authorization | None:
        auth_id = self._ticket_latest.get(ticket_no)
        return None if auth_id is None else self._by_id[auth_id]

    def require_ticket(self, ticket_no: str) -> Authorization:
        authorization = self.find_ticket(ticket_no)
        if authorization is None:
            raise NotFoundError("authorization ticket does not exist", ticket_no=ticket_no)
        return authorization

    def find_request(self, request_id: str) -> Authorization | None:
        auth_id = self._request_index.get(request_id)
        return None if auth_id is None else self._by_id[auth_id]

    def all(self) -> tuple[Authorization, ...]:
        return tuple(self._by_id.values())

    def describe(self, now: int) -> dict[str, object]:
        authorizations = sorted(self._by_id.values(), key=lambda item: item.issued_tick)
        return {
            "count": len(authorizations),
            "active": [item.describe(now) for item in authorizations if item.is_valid(now)],
            "authorizations": [item.describe(now) for item in authorizations],
        }
