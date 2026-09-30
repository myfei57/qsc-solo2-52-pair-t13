"""One-time authorization lifecycle and persistence rules."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from mixplant.authz.service import ACTION_KIND, AUTHORIZATION_KIND
from mixplant.config import StationConfig
from mixplant.console.pages import PageStore
from mixplant.console.router import Request
from mixplant.console.server import ConsoleServer
from mixplant.errors import AuthorizationError
from mixplant.runtime import PlantRuntime
from tests.support import run


def _issue(runtime: PlantRuntime, ticket: str = "W-1", *, auth_type: str = "warehouse_open", ttl: int = 5):
    return run(
        runtime,
        "authz.issue",
        {"ticket_no": ticket, "type": auth_type, "ttl_ticks": ttl},
    )


def test_authorization_is_redeemed_once_and_recorded_with_the_gate_action(runtime: PlantRuntime) -> None:
    issued = _issue(runtime)["authorization"]
    result = run(runtime, "authz.redeem", {"ticket_no": "W-1", "request_id": "req-1"})

    assert result["action"] == "warehouse.open"
    assert result["idempotent"] is False
    assert result["authorization"]["status"] == "redeemed"
    assert run(runtime, "authz.get", {"ticket_no": "W-1"})["status"] == "redeemed"

    kinds = [record.kind for record in runtime.store.committed_records()[-3:]]
    assert kinds == [AUTHORIZATION_KIND, ACTION_KIND, "audit.entry"]

    trail = run(runtime, "authz.audit", {"auth_id": issued["auth_id"]})["entries"]
    assert [entry["name"] for entry in trail] == [
        "authorization.issued",
        "authorization.redeemed",
    ]
    assert runtime.state()["subsystems"]["authz"]["active"] == []


def test_warehouse_open_rejects_a_second_use_even_with_a_new_request(runtime: PlantRuntime) -> None:
    _issue(runtime)
    run(runtime, "authz.redeem", {"ticket_no": "W-1", "request_id": "req-1"})

    with pytest.raises(AuthorizationError) as blocked:
        run(runtime, "authz.redeem", {"ticket_no": "W-1", "request_id": "req-2"})
    assert blocked.value.context["policy"] == "reject"


def test_gate_release_voids_the_consumed_slip_and_reopens_a_revision(runtime: PlantRuntime) -> None:
    first = _issue(runtime, "G-1", auth_type="gate_release")["authorization"]
    run(runtime, "authz.redeem", {"ticket_no": "G-1", "request_id": "req-1"})
    result = run(runtime, "authz.redeem", {"ticket_no": "G-1", "request_id": "req-2"})

    assert result["previous"]["auth_id"] == first["auth_id"]
    assert result["previous"]["status"] == "voided"
    assert result["authorization"]["status"] == "redeemed"
    assert result["authorization"]["replacement_for"] == first["auth_id"]
    assert result["action"] == "gate.release"

    stored = run(runtime, "authz.get", {"ticket_no": "G-1"})
    assert stored["auth_id"] == result["authorization"]["auth_id"]
    prior = run(runtime, "authz.get", {"auth_id": first["auth_id"]})
    assert prior["status"] == "voided"
    assert prior["replaced_by"] == stored["auth_id"]
    assert len([r for r in runtime.store.committed_records() if r.kind == ACTION_KIND]) == 2


def test_concurrent_redeems_with_the_same_request_are_idempotent(runtime: PlantRuntime) -> None:
    _issue(runtime)

    def redeem() -> dict:
        return run(runtime, "authz.redeem", {"ticket_no": "W-1", "request_id": "req-1"})

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: redeem(), range(8)))

    assert [item["authorization"]["auth_id"] for item in results].count(results[0]["authorization"]["auth_id"]) == 8
    assert [item["action"] for item in results].count("warehouse.open") == 8
    assert sum(item["idempotent"] for item in results) == 7
    assert len([r for r in runtime.store.committed_records() if r.kind == ACTION_KIND]) == 1


def test_concurrent_redeems_for_a_reopenable_slip_succeed_once_per_request(runtime: PlantRuntime) -> None:
    _issue(runtime, "G-1", auth_type="gate_release")

    def redeem(request_id: str) -> dict:
        return run(runtime, "authz.redeem", {"ticket_no": "G-1", "request_id": request_id})

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: redeem("same-request"), range(8)))

    assert len({item["authorization"]["auth_id"] for item in results}) == 1
    assert len([r for r in runtime.store.committed_records() if r.kind == ACTION_KIND]) == 1


def test_redeem_request_id_cannot_be_reused_for_another_ticket(runtime: PlantRuntime) -> None:
    _issue(runtime, "W-1")
    _issue(runtime, "W-2")
    run(runtime, "authz.redeem", {"ticket_no": "W-1", "request_id": "req-1"})

    with pytest.raises(AuthorizationError):
        run(runtime, "authz.redeem", {"ticket_no": "W-2", "request_id": "req-1"})


def test_expired_authorizations_are_swept_in_real_time_on_access(runtime: PlantRuntime) -> None:
    issued = _issue(runtime, ttl=3)["authorization"]
    run(runtime, "clock.advance", {"ticks": 3})

    assert run(runtime, "authz.status")["expiry_policy"] == "realtime_on_access"
    assert run(runtime, "authz.get", {"ticket_no": "W-1"})["status"] == "expired"
    with pytest.raises(AuthorizationError):
        run(runtime, "authz.redeem", {"ticket_no": "W-1", "request_id": "req-1"})

    with pytest.raises(AuthorizationError):
        run(runtime, "authz.return", {"auth_id": issued["auth_id"]})

    names = [entry["name"] for entry in run(runtime, "authz.audit", {"ticket_no": "W-1"})["entries"]]
    assert names[-1] == "authorization.expired"


def test_returned_and_voided_slips_cannot_be_used_or_reissued(runtime: PlantRuntime) -> None:
    issued = _issue(runtime, "W-9")["authorization"]
    run(runtime, "authz.return", {"auth_id": issued["auth_id"]})

    with pytest.raises(AuthorizationError):
        run(runtime, "authz.redeem", {"ticket_no": "W-9", "request_id": "req-1"})
    with pytest.raises(AuthorizationError):
        _issue(runtime, "W-9")

    other = _issue(runtime, "W-10")["authorization"]
    run(runtime, "authz.void", {"ticket_no": "W-10", "reason": "wrong door"})
    with pytest.raises(AuthorizationError):
        run(runtime, "authz.redeem", {"ticket_no": "W-10", "request_id": "req-2"})
    assert run(runtime, "authz.get", {"auth_id": other["auth_id"]})["status"] == "voided"


def test_authorization_state_restarts_from_the_journal(tmp_path) -> None:
    runtime = PlantRuntime(StationConfig(web_dir=tmp_path / "web", data_dir=tmp_path / "state"), storage="file")
    runtime.bootstrap()
    issued = _issue(runtime, "W-2")["authorization"]
    run(runtime, "authz.redeem", {"ticket_no": "W-2", "request_id": "req-1"})
    action_count = len([r for r in runtime.store.committed_records() if r.kind == ACTION_KIND])
    runtime.close()

    restarted = PlantRuntime(
        StationConfig(web_dir=tmp_path / "web", data_dir=tmp_path / "state"), storage="file"
    )
    restarted.bootstrap()

    assert restarted.authz.get(ticket_no="W-2")["auth_id"] == issued["auth_id"]
    assert restarted.authz.get(ticket_no="W-2")["status"] == "redeemed"
    assert restarted.ids.issued("auth") == 1
    assert len([r for r in restarted.store.committed_records() if r.kind == ACTION_KIND]) == action_count


def test_console_exposes_authorization_state_and_routes(runtime: PlantRuntime) -> None:
    _issue(runtime)
    server = ConsoleServer(runtime, pages=PageStore(runtime.config.web_dir))

    state = server.handle(Request(method="GET", path="/api/authz"))
    assert state.ok is True
    assert json.loads(state.text)["result"]["count"] == 1

    response = server.handle(
        Request(method="POST", path="/api/authz/redeem", body={"ticket_no": "W-1", "request_id": "req-1"})
    )
    assert response.ok is True
    assert json.loads(response.text)["result"]["action"] == "warehouse.open"
