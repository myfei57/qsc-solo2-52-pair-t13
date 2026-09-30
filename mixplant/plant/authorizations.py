"""Read model for the authorization console page."""

from __future__ import annotations

from typing import Any


def authorization_view(auth_service: Any) -> dict[str, Any]:
    """Turn the authorization service into the document the page renders."""

    snapshot = auth_service.describe()
    return {
        "counts": dict(snapshot.get("counts", {})),
        "due_for_expiry": list(snapshot.get("due_for_expiry", [])),
        "gate_actions": list(auth_service.gate_actions()),
        "tickets": list(snapshot.get("tickets", [])),
    }
