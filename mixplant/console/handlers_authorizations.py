"""Routes for issuing, redeeming, revoking and reopening authorizations."""

from __future__ import annotations

from typing import Any

from .response import inject_snapshot
from .router import Request, Response, Router

COMMANDS = (
    ("POST", "/api/auth/issue", "auth.issue"),
    ("POST", "/api/auth/redeem", "auth.redeem"),
    ("POST", "/api/auth/revoke", "auth.revoke"),
    ("POST", "/api/auth/reopen", "auth.reopen"),
    ("POST", "/api/auth/expire", "auth.expire"),
    ("POST", "/api/auth/sweep", "auth.sweep"),
)


def register(router: Router, runtime: Any, pages: Any) -> None:
    """Register the authorization routes."""

    router.add(
        "GET",
        "/pages/authorizations",
        lambda _: Response.html(
            inject_snapshot(pages.load("authorizations"), runtime.controller.authorization_view())
        ),
    )
    router.add("GET", "/api/auth", lambda _: Response.json(runtime.controller.authorization_view()))
    for method, path, command in COMMANDS:
        router.add(method, path, _command(runtime, command))


def _command(runtime: Any, command: str):
    def handler(request: Request) -> Response:
        return Response.json(runtime.dispatch(command, dict(request.body)))

    return handler
