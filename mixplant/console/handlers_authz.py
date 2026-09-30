"""Routes for one-time warehouse and gate authorizations."""

from __future__ import annotations

from typing import Any

from .router import Request, Response, Router

COMMANDS = (
    ("POST", "/api/authz/issue", "authz.issue"),
    ("POST", "/api/authz/redeem", "authz.redeem"),
    ("POST", "/api/authz/return", "authz.return"),
    ("POST", "/api/authz/void", "authz.void"),
)


def register(router: Router, runtime: Any, pages: Any) -> None:
    """Register authorization routes."""

    del pages
    router.add("GET", "/api/authz", lambda _: Response.json(runtime.dispatch("authz.status", {})))
    router.add(
        "GET",
        "/api/authz/audit",
        lambda request: Response.json(
            runtime.dispatch(
                "authz.audit",
                {
                    "auth_id": request.query.get("auth_id"),
                    "ticket_no": request.query.get("ticket_no"),
                },
            )
        ),
    )
    router.add(
        "GET",
        "/api/authz/ticket/{ticket_no}",
        lambda request: Response.json(
            runtime.dispatch("authz.get", {"ticket_no": request.params["ticket_no"]})
        ),
    )
    for method, path, command in COMMANDS:
        router.add(method, path, _command(runtime, command))


def _command(runtime: Any, command: str):
    def handler(request: Request) -> Response:
        return Response.json(runtime.dispatch(command, dict(request.body)))

    return handler
