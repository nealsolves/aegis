"""Single-process AuditChain reservation and reconciliation tests."""

from __future__ import annotations

import threading
import time

import pytest

from aegis._internal.audit_chain import AuditChain
from aegis._internal.chain_linker import ChainLinkRequest
from aegis._internal.evidence_profiles import build_content_checksum_v2
from aegis._internal.errors import ChainLinkError


def _request(attempt_id=0):
    return ChainLinkRequest(
        attempt_id=attempt_id,
        artifact_type="invocation",
        correlation_id=f"correlation-{attempt_id}",
    )


def _observed_artifact(coordinates):
    return build_content_checksum_v2(
        {
            "audit_schema_version": "2.0",
            "canonicalization_profile": "aegis-json-v2",
            "chain_id": coordinates.chain_id,
            "chain_index": coordinates.chain_index,
            "previous_audit_checksum": coordinates.previous_audit_checksum,
            "reservation_id": coordinates.reservation_id,
            "body": {"result": "PASS"},
        }
    )


@pytest.mark.parametrize("chain_id", ["", "   "])
def test_explicit_blank_chain_identity_is_rejected(chain_id):
    with pytest.raises(ChainLinkError) as exc_info:
        AuditChain(chain_id=chain_id)

    assert exc_info.value.code == "CHAIN_COORDINATES_INVALID"


def test_commit_advances_index_and_prior_content_checksum():
    chain = AuditChain(chain_id="tenant-audit")
    first = chain.reserve(_request(1), timeout=0.1)

    assert first.coordinates.chain_id == "tenant-audit"
    assert first.coordinates.chain_index == 0
    assert first.coordinates.previous_audit_checksum is None
    assert len(first.coordinates.reservation_id) == 32

    first.commit("a" * 64)
    second = chain.reserve(_request(2), timeout=0.1)

    assert second.coordinates.chain_index == 1
    assert second.coordinates.previous_audit_checksum == "a" * 64


def test_abort_releases_slot_without_index_gap():
    chain = AuditChain(chain_id="tenant-audit")
    abandoned = chain.reserve(_request(1), timeout=0.1)
    abandoned.abort()

    retried = chain.reserve(_request(2), timeout=0.1)

    assert retried.coordinates.chain_index == 0
    assert retried.coordinates.previous_audit_checksum is None
    assert retried.coordinates.reservation_id != (
        abandoned.coordinates.reservation_id
    )


def test_second_reservation_wait_is_bounded_while_predecessor_is_pending():
    chain = AuditChain(chain_id="tenant-audit")
    first = chain.reserve(_request(1), timeout=0.1)
    result = []

    def reserve_second():
        started = time.monotonic()
        try:
            chain.reserve(_request(2), timeout=0.05)
        except ChainLinkError as exc:
            result.append((exc.code, time.monotonic() - started))

    waiter = threading.Thread(target=reserve_second)
    waiter.start()
    waiter.join(timeout=0.5)
    first.abort()

    assert not waiter.is_alive()
    assert result[0][0] == "CHAIN_LINK_TIMEOUT"
    assert 0.04 <= result[0][1] < 0.5


def test_commit_and_abort_terminal_transitions_are_idempotent_and_closed():
    chain = AuditChain()
    committed = chain.reserve(_request(1), timeout=0.1)
    committed.commit("a" * 64)
    committed.commit("a" * 64)

    with pytest.raises(ChainLinkError) as commit_conflict:
        committed.commit("b" * 64)
    assert commit_conflict.value.code == "CHAIN_RESERVATION_CONFLICT"
    with pytest.raises(ChainLinkError) as abort_conflict:
        committed.abort()
    assert abort_conflict.value.code == "CHAIN_RESERVATION_CONFLICT"

    aborted = chain.reserve(_request(2), timeout=0.1)
    aborted.abort()
    aborted.abort()
    with pytest.raises(ChainLinkError) as aborted_commit:
        aborted.commit("b" * 64)
    assert aborted_commit.value.code == "CHAIN_RESERVATION_CONFLICT"


@pytest.mark.parametrize("checksum", [None, True, "signature", "A" * 64])
def test_malformed_content_checksum_does_not_consume_reservation(checksum):
    chain = AuditChain()
    reservation = chain.reserve(_request(), timeout=0.1)

    with pytest.raises(ChainLinkError) as exc_info:
        reservation.commit(checksum)

    assert exc_info.value.code == "CHAIN_CONTENT_CHECKSUM_INVALID"
    reservation.commit("c" * 64)
    assert chain.length == 1


def test_reconcile_observed_artifact_commits_emit_commit_crash_window():
    chain = AuditChain()
    reservation = chain.reserve(_request(), timeout=0.1)
    observed = _observed_artifact(reservation.coordinates)

    chain.reconcile(reservation.coordinates.reservation_id, observed)
    chain.reconcile(reservation.coordinates.reservation_id, observed)

    next_reservation = chain.reserve(_request(2), timeout=0.1)
    assert next_reservation.coordinates.chain_index == 1
    assert next_reservation.coordinates.previous_audit_checksum == (
        observed["checksum"]
    )


def test_reconcile_confirmed_absence_aborts_without_advancing():
    chain = AuditChain()
    reservation = chain.reserve(_request(), timeout=0.1)

    chain.reconcile(reservation.coordinates.reservation_id, None)
    chain.reconcile(reservation.coordinates.reservation_id, None)

    retried = chain.reserve(_request(2), timeout=0.1)
    assert retried.coordinates.chain_index == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda artifact: artifact.update(reservation_id="other"),
        lambda artifact: artifact.update(chain_index=99),
        lambda artifact: artifact.update(checksum="0" * 64),
    ],
)
def test_reconcile_contradiction_fails_closed_and_keeps_slot_quarantined(mutate):
    chain = AuditChain()
    reservation = chain.reserve(_request(), timeout=0.1)
    observed = _observed_artifact(reservation.coordinates)
    mutate(observed)

    with pytest.raises(ChainLinkError) as exc_info:
        chain.reconcile(reservation.coordinates.reservation_id, observed)

    assert exc_info.value.code == "CHAIN_RECONCILIATION_FAILED"
    with pytest.raises(ChainLinkError) as timeout:
        chain.reserve(_request(2), timeout=0.01)
    assert timeout.value.code == "CHAIN_LINK_TIMEOUT"
    reservation.abort()


def test_unknown_reconciliation_identity_fails_closed():
    chain = AuditChain()

    with pytest.raises(ChainLinkError) as exc_info:
        chain.reconcile("unknown-reservation", None)

    assert exc_info.value.code == "CHAIN_RESERVATION_NOT_FOUND"
