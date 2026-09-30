"""Single use authorizations: one redemption, real time expiry, idempotency.

The rules under test are:
* a ticket is redeemed at most once and is dead the instant it is consumed;
* expired tickets are cleared in real time (at present) and swept when the
  clock advances, and can never open a gate;
* a returned (revoked) or used ticket can never be brought back;
* reuse is refused or allowed as "void then reopen" depending on the type;
* concurrent redemptions of one ticket are idempotent, succeeding exactly
  once;
* the ticket status, the gate action and the audit ledger all agree.
"""

from __future__ import annotations

import threading

import pytest

from mixplant.errors import (
    AuthorizationConsumedError,
    AuthorizationExpiredError,
    AuthorizationReuseRejectedError,
)
from mixplant.auth.ticket import EXPIRED, ISSUED, REDEEMED, REOPENABLE, REVOKED, STRICT
from tests.support import advance_to_mixed, run


def _ready_to_open(runtime, truck="T-01") -> str:
    """Drive the plant to a finished mix with one queued truck."""

    advance_to_mixed(runtime)
    run(runtime, "chute.arrive", {"truck_id": truck})
    return truck


def test_issue_then_redeem_opens_the_gate_once(runtime) -> None:
    _ready_to_open(runtime)
    ticket_id = run(runtime, "auth.issue", {"action": "chute.open"})["ticket"]["ticket_id"]

    result = run(runtime, "auth.redeem", {"ticket_id": ticket_id, "request_id": "r1"})
    assert result["redeemed"]["status"] == REDEEMED
    assert result["gate"]["door"]["active"] is True
    assert runtime.state()["facts"]["chute.door_open"] is True


def test_redeeming_twice_with_the_same_request_id_is_idempotent(runtime) -> None:
    _ready_to_open(runtime)
    ticket_id = run(runtime, "auth.issue", {"action": "chute.open"})["ticket"]["ticket_id"]
    first = run(runtime, "auth.redeem", {"ticket_id": ticket_id, "request_id": "dup"})
    second = run(runtime, "auth.redeem", {"ticket_id": ticket_id, "request_id": "dup"})
    assert first["redeemed"]["status"] == REDEEMED
    assert second["idempotent"] is True
    assert second["seq"] == first["seq"]
    # the gate ran a single time: only one redeemed record exists
    redeems = [r for r in runtime.store.visible() if r.kind == "auth.redeem"]
    assert len(redeems) == 1


def test_strict_ticket_reuse_is_refused(runtime) -> None:
    _ready_to_open(runtime)
    ticket_id = run(
        runtime, "auth.issue", {"action": "chute.open", "reuse_policy": STRICT}
    )["ticket"]["ticket_id"]
    run(runtime, "auth.redeem", {"ticket_id": ticket_id, "request_id": "a"})
    with pytest.raises(AuthorizationReuseRejectedError):
        run(runtime, "auth.redeem", {"ticket_id": ticket_id, "request_id": "b"})
    # refusal is alarmed and copied into the audit ledger
    assert any(e.name == "auth.reuse_rejected" for e in runtime.audit.ledger.entries())


def test_reopenable_ticket_reuse_is_still_consumed_but_can_be_reopened(runtime) -> None:
    _ready_to_open(runtime)
    ticket_id = run(
        runtime, "auth.issue", {"action": "chute.open", "reuse_policy": REOPENABLE}
    )["ticket"]["ticket_id"]
    run(runtime, "auth.redeem", {"ticket_id": ticket_id})
    # the old id never works again, even for a reopenable ticket
    with pytest.raises(AuthorizationConsumedError):
        run(runtime, "auth.redeem", {"ticket_id": ticket_id})
    # reopening an already consumed reopenable ticket hands out a fresh id
    reopened = run(runtime, "auth.reopen", {"ticket_id": ticket_id})
    new_id = reopened["ticket"]["ticket_id"]
    assert new_id != ticket_id
    assert runtime.auth.tickets.get(ticket_id).status == REDEEMED


def test_strict_ticket_cannot_be_reopened(runtime) -> None:
    _ready_to_open(runtime)
    ticket_id = run(
        runtime, "auth.issue", {"action": "chute.open", "reuse_policy": STRICT}
    )["ticket"]["ticket_id"]
    with pytest.raises(AuthorizationReuseRejectedError):
        run(runtime, "auth.reopen", {"ticket_id": ticket_id})
    assert runtime.auth.tickets.get(ticket_id).status == ISSUED


def test_revoke_voids_a_ticket_and_a_terminal_ticket_never_returns(runtime) -> None:
    _ready_to_open(runtime)
    ticket_id = run(runtime, "auth.issue", {"action": "chute.open"})["ticket"]["ticket_id"]
    run(runtime, "auth.revoke", {"ticket_id": ticket_id, "reason": "truck left"})
    assert runtime.auth.tickets.get(ticket_id).status == REVOKED
    with pytest.raises(AuthorizationConsumedError):
        run(runtime, "auth.redeem", {"ticket_id": ticket_id})
    # revoking again, or reopening the terminal ticket, does not revive it
    with pytest.raises(AuthorizationConsumedError):
        run(runtime, "auth.revoke", {"ticket_id": ticket_id})


def test_reopen_voids_issued_ticket_and_old_id_is_dead(runtime) -> None:
    _ready_to_open(runtime)
    old_id = run(
        runtime, "auth.issue", {"action": "chute.open", "reuse_policy": REOPENABLE}
    )["ticket"]["ticket_id"]
    new_id = run(runtime, "auth.reopen", {"ticket_id": old_id})["ticket"]["ticket_id"]
    assert new_id != old_id
    assert runtime.auth.tickets.get(old_id).status == REVOKED
    assert runtime.auth.tickets.get(old_id).replacement_id == new_id
    with pytest.raises(AuthorizationConsumedError):
        run(runtime, "auth.redeem", {"ticket_id": old_id})
    assert runtime.auth.tickets.get(new_id).status == ISSUED


def test_expired_ticket_is_rejected_in_real_time_at_redeem(runtime) -> None:
    _ready_to_open(runtime)
    ticket_id = run(
        runtime, "auth.issue", {"action": "chute.open", "ttl_ticks": 1}
    )["ticket"]["ticket_id"]
    run(runtime, "clock.advance", {"ticks": 2})
    # even without an explicit sweep, present time says the ticket is dead
    with pytest.raises(AuthorizationExpiredError):
        run(runtime, "auth.redeem", {"ticket_id": ticket_id})
    assert runtime.auth.tickets.get(ticket_id).status == EXPIRED


def test_clock_advance_sweeps_expired_tickets(runtime) -> None:
    _ready_to_open(runtime)
    short = run(
        runtime, "auth.issue", {"action": "chute.open", "ttl_ticks": 1}
    )["ticket"]["ticket_id"]
    keep = run(
        runtime, "auth.issue", {"action": "chute.open", "ttl_ticks": 10}
    )["ticket"]["ticket_id"]
    run(runtime, "clock.advance", {"ticks": 2})
    assert runtime.auth.tickets.get(short).status == EXPIRED
    assert runtime.auth.tickets.get(keep).status == ISSUED
    counts = runtime.state()["authorizations"]["counts"]
    assert counts["expired"] == 1
    assert counts["issued"] == 1


def test_explicit_sweep_is_idempotent(runtime) -> None:
    _ready_to_open(runtime)
    run(runtime, "auth.issue", {"action": "chute.open", "ttl_ticks": 1})
    run(runtime, "clock.advance", {"ticks": 2})
    again = run(runtime, "auth.sweep")
    assert again["count"] == 0


def test_concurrent_redemption_succeeds_exactly_once(runtime) -> None:
    _ready_to_open(runtime)
    ticket_id = run(
        runtime, "auth.issue", {"action": "chute.open", "reuse_policy": STRICT}
    )["ticket"]["ticket_id"]
    outcomes: list[str] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        try:
            run(runtime, "auth.redeem", {"ticket_id": ticket_id, "request_id": f"w{index}"})
            code = "ok"
        except AuthorizationReuseRejectedError:
            code = "rejected"
        with lock:
            outcomes.append(code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert outcomes.count("ok") == 1
    assert outcomes.count("rejected") == 15
    assert runtime.auth.tickets.get(ticket_id).status == REDEEMED


def test_status_gate_and_audit_agree(runtime) -> None:
    _ready_to_open(runtime)
    ticket_id = run(runtime, "auth.issue", {"action": "chute.open"})["ticket"]["ticket_id"]
    run(runtime, "auth.redeem", {"ticket_id": ticket_id})

    # status
    assert runtime.auth.tickets.get(ticket_id).status == REDEEMED
    # gate action durable in the derived facts
    assert runtime.state()["facts"]["chute.door_open"] is True
    # audit ledger/stream: issue and redeem both announced and copied
    names = {
        record.payload.get("name")
        for record in runtime.store.history("audit.event")
        if record.origin == "auth"
    }
    assert {"auth.ticket_issued", "auth.ticket_redeemed"} <= names


def test_authorizations_are_served_to_the_console(runtime) -> None:
    run(runtime, "auth.issue", {"action": "chute.open"})
    snapshot = runtime.state()["authorizations"]
    assert snapshot["counts"]["issued"] == 1
    assert snapshot["tickets"][0]["action"] == "chute.open"
    page = runtime.controller.authorization_view()
    assert page["tickets"][0]["ticket_id"].startswith("auth-")


def test_ticket_survives_restart_in_its_terminal_state(tmp_path) -> None:
    from pathlib import Path

    from mixplant.config import StationConfig
    from mixplant.runtime import PlantRuntime

    config = StationConfig(web_dir=Path("web"), data_dir=tmp_path)
    first = PlantRuntime(config, storage="file")
    first.bootstrap()
    _ready_to_open(first)
    strict_id = run(
        first, "auth.issue", {"action": "chute.open", "reuse_policy": STRICT, "ttl_ticks": 99}
    )["ticket"]["ticket_id"]
    reopen_id = run(
        first, "auth.issue", {"action": "chute.open", "reuse_policy": REOPENABLE, "ttl_ticks": 99}
    )["ticket"]["ticket_id"]
    run(first, "auth.redeem", {"ticket_id": strict_id, "request_id": "persist"})
    replacement = run(first, "auth.reopen", {"ticket_id": reopen_id})["ticket"]["ticket_id"]
    first.close()

    second = PlantRuntime(config, storage="file")
    second.bootstrap()
    assert second.auth.tickets.get(strict_id).status == REDEEMED
    assert second.auth.tickets.get(reopen_id).status == REVOKED
    assert second.auth.tickets.get(reopen_id).replacement_id == replacement
    assert second.auth.tickets.get(replacement).status == ISSUED
    # the idempotency key still replays the recorded outcome
    assert second.auth.tickets.replay_result("persist") is not None
    # id counters continue, so a new ticket cannot reuse an old id
    next_id = run(second, "auth.issue", {"action": "chute.open"})["ticket"]["ticket_id"]
    assert next_id not in {strict_id, reopen_id, replacement}
