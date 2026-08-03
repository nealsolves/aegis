"""Closed host-owned chain linker contract tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from aegis._internal.chain_linker import (
    ChainCoordinates,
    ChainLinkRequest,
    validate_chain_coordinates,
)
from aegis._internal.errors import ChainLinkError


def test_valid_first_coordinate_set_is_normalized_to_frozen_value():
    coordinates = validate_chain_coordinates(
        {
            "chain_id": "tenant-audit",
            "chain_index": 0,
            "previous_audit_checksum": None,
            "reservation_id": "7f0d6d81b5b44948a10618681e7ad559",
        }
    )

    assert coordinates == ChainCoordinates(
        chain_id="tenant-audit",
        chain_index=0,
        previous_audit_checksum=None,
        reservation_id="7f0d6d81b5b44948a10618681e7ad559",
    )
    with pytest.raises(FrozenInstanceError):
        coordinates.chain_index = 1  # type: ignore[misc]


def test_valid_prefix_coordinate_requires_prior_v2_content_checksum():
    coordinates = validate_chain_coordinates(
        ChainCoordinates(
            chain_id="tenant-audit",
            chain_index=7,
            previous_audit_checksum="a" * 64,
            reservation_id="323651a2f7fd44aca35a97266d6bff87",
        )
    )

    assert coordinates.chain_index == 7
    assert coordinates.previous_audit_checksum == "a" * 64


@pytest.mark.parametrize(
    ("coordinates", "expected_code"),
    [
        ({"chain_id": "c", "chain_index": 1}, "CHAIN_COORDINATES_INVALID"),
        (
            {
                "chain_id": "",
                "chain_index": 0,
                "previous_audit_checksum": None,
                "reservation_id": "reservation",
            },
            "CHAIN_COORDINATES_INVALID",
        ),
        (
            {
                "chain_id": "c",
                "chain_index": -1,
                "previous_audit_checksum": None,
                "reservation_id": "reservation",
            },
            "CHAIN_COORDINATES_INVALID",
        ),
        (
            {
                "chain_id": "c",
                "chain_index": True,
                "previous_audit_checksum": None,
                "reservation_id": "reservation",
            },
            "CHAIN_COORDINATES_INVALID",
        ),
        (
            {
                "chain_id": "c",
                "chain_index": 1,
                "previous_audit_checksum": "signature-value",
                "reservation_id": "reservation",
            },
            "CHAIN_PREVIOUS_INVALID",
        ),
        (
            {
                "chain_id": "c",
                "chain_index": 0,
                "previous_audit_checksum": "a" * 64,
                "reservation_id": "reservation",
            },
            "CHAIN_PREVIOUS_INVALID",
        ),
        (
            {
                "chain_id": "c",
                "chain_index": 1,
                "previous_audit_checksum": "A" * 64,
                "reservation_id": "reservation",
            },
            "CHAIN_PREVIOUS_INVALID",
        ),
        (
            {
                "chain_id": "c",
                "chain_index": 0,
                "previous_audit_checksum": None,
                "reservation_id": "",
            },
            "CHAIN_COORDINATES_INVALID",
        ),
        (
            {
                "chain_id": "c",
                "chain_index": 0,
                "previous_audit_checksum": None,
                "reservation_id": "r" * 513,
            },
            "CHAIN_COORDINATES_INVALID",
        ),
        (
            {
                "chain_id": "c",
                "chain_index": 0,
                "previous_audit_checksum": None,
                "reservation_id": "reservation",
                "unexpected": "field",
            },
            "CHAIN_COORDINATES_INVALID",
        ),
        (None, "CHAIN_COORDINATES_INVALID"),
    ],
)
def test_invalid_coordinates_fail_closed(coordinates, expected_code):
    with pytest.raises(ChainLinkError) as exc_info:
        validate_chain_coordinates(coordinates)

    assert exc_info.value.code == expected_code


@pytest.mark.parametrize(
    ("kwargs", "expected_code"),
    [
        (
            {"attempt_id": True, "artifact_type": "invocation", "correlation_id": None},
            "CHAIN_LINK_REQUEST_INVALID",
        ),
        (
            {"attempt_id": -1, "artifact_type": "invocation", "correlation_id": None},
            "CHAIN_LINK_REQUEST_INVALID",
        ),
        (
            {"attempt_id": 1, "artifact_type": "workflow", "correlation_id": None},
            "CHAIN_ARTIFACT_INELIGIBLE",
        ),
        (
            {"attempt_id": 1, "artifact_type": "invocation", "correlation_id": 7},
            "CHAIN_LINK_REQUEST_INVALID",
        ),
        (
            {
                "attempt_id": 1,
                "artifact_type": "invocation",
                "correlation_id": "c" * 513,
            },
            "CHAIN_LINK_REQUEST_INVALID",
        ),
    ],
)
def test_invalid_link_requests_fail_closed(kwargs, expected_code):
    with pytest.raises(ChainLinkError) as exc_info:
        ChainLinkRequest(**kwargs)

    assert exc_info.value.code == expected_code


def test_invocation_link_request_accepts_bounded_optional_correlation():
    request = ChainLinkRequest(
        attempt_id=9,
        artifact_type="invocation",
        correlation_id="workflow-correlation-9",
    )

    assert request.attempt_id == 9
    assert request.artifact_type == "invocation"
    assert request.correlation_id == "workflow-correlation-9"


def test_host_linker_contract_is_available_from_the_stable_package():
    import aegis

    expected = {
        "ChainCoordinates",
        "ChainLinkError",
        "ChainLinker",
        "ChainLinkRequest",
        "ChainReservation",
    }

    assert expected <= set(aegis.__all__)
    for name in expected:
        assert getattr(aegis, name) is not None
