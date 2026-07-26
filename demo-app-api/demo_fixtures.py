"""Immutable, fictional fixtures for the deterministic governance roleplays."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


FIXTURE_VERSION = "2026-07-25.1"

# Fixed non-production test material. Never reuse this key outside the demo.
ATLAS_DEMO_ONLY_SIGNING_KEY = b"aegis-atlas-demo-only-hmac-key-v1"


@dataclass(frozen=True)
class ScenarioFixture:
    scenario_id: str
    variant: str
    participant: str
    role: str
    prompt: str
    output: dict[str, Any]
    context: dict[str, Any]
    transcript: tuple[dict[str, str], ...]


SCENARIO_FIXTURES: dict[tuple[str, str], ScenarioFixture] = {
    ("atlas", "first_attempt"): ScenarioFixture(
        scenario_id="atlas",
        variant="first_attempt",
        participant="atlas-support-01",
        role="support",
        prompt="Review fictional refund case AT-104 under the supplied policy.",
        output={
            "reply": "The fictional refund request is ready for approved review.",
            "refund_commitment": (
                "Approved review may proceed after policy attribution."
            ),
        },
        context={
            "customer_verified": True,
            "refund_approved": True,
            "fictional_case_id": "AT-104",
        },
        transcript=(
            {
                "speaker": "Support lead",
                "text": "Review fictional refund case AT-104.",
            },
            {
                "speaker": "Atlas",
                "text": "The first response omitted required provenance.",
            },
        ),
    ),
    ("atlas", "corrected"): ScenarioFixture(
        scenario_id="atlas",
        variant="corrected",
        participant="atlas-support-01",
        role="support",
        prompt="Review fictional refund case AT-104 under the supplied policy.",
        output={
            "policy_citation": "BRV-04",
            "refund_commitment": (
                "Approved review may proceed under fictional policy BRV-04."
            ),
            "reply": "The fictional refund request is ready for approved review.",
        },
        context={
            "customer_verified": True,
            "refund_approved": True,
            "fictional_case_id": "AT-104",
            "provenance": {"source_ids": ["atlas-policy-BRV-04"]},
        },
        transcript=(
            {
                "speaker": "Support lead",
                "text": "Retry with the fictional policy source attached.",
            },
            {
                "speaker": "Atlas",
                "text": "The response now cites BRV-04 and retains approval.",
            },
        ),
    ),
    ("northstar", "first_attempt"): ScenarioFixture(
        scenario_id="northstar",
        variant="first_attempt",
        participant="northstar-scheduler-01",
        role="scheduling_assistant",
        prompt="Prepare a scheduling-only summary for fictional record NS-204.",
        output={
            "summary": "Fictional record NS-204 is ready for scheduling review.",
            "scheduling_only": True,
        },
        context={
            "fictional_record_id": "NS-204",
            "privacy_scope": "scheduling_only",
        },
        transcript=(
            {
                "speaker": "Clinic coordinator",
                "text": "Prepare a scheduling-only summary for record NS-204.",
            },
            {
                "speaker": "Northstar",
                "text": "The scheduling-assistant role requested clinical access.",
            },
        ),
    ),
    ("northstar", "authorized_retry"): ScenarioFixture(
        scenario_id="northstar",
        variant="authorized_retry",
        participant="northstar-nurse-01",
        role="nurse",
        prompt="Prepare a scheduling-only summary for fictional record NS-204.",
        output={
            "clinical_recommendation": (
                "Recommend a physician review before changing the appointment type."
            ),
            "summary": "Fictional record NS-204 needs physician review.",
        },
        context={
            "fictional_record_id": "NS-204",
            "privacy_scope": "scheduling_only",
        },
        transcript=(
            {
                "speaker": "Clinic coordinator",
                "text": "Retry as the authorized nurse for record NS-204.",
            },
            {
                "speaker": "Northstar",
                "text": "The retry exceeded scheduling scope and needs approval.",
            },
        ),
    ),
    ("northstar", "corrected"): ScenarioFixture(
        scenario_id="northstar",
        variant="corrected",
        participant="northstar-nurse-01",
        role="nurse",
        prompt="Prepare a scheduling-only summary for fictional record NS-204.",
        output={
            "scheduling_only": True,
            "summary": (
                "Fictional record NS-204 is ready for "
                "physician-approved scheduling."
            ),
        },
        context={
            "fictional_record_id": "NS-204",
            "privacy_scope": "scheduling_only",
            "physician_approval_recorded": True,
        },
        transcript=(
            {
                "speaker": "Fictional physician reviewer",
                "text": "Scheduling-only scope is approved for record NS-204.",
            },
            {
                "speaker": "Northstar",
                "text": "The limited scheduling summary is ready.",
            },
        ),
    ),
    ("meridian", "first_attempt"): ScenarioFixture(
        scenario_id="meridian",
        variant="first_attempt",
        participant="meridian-invoice-01",
        role="accounts_payable",
        prompt="Process fictional invoice MV-248 through the governed workflow.",
        output={
            "invoice_intake": {
                "record": "Fictional invoice MV-248 was received.",
                "status": "recorded",
                "step_id": "invoice_intake",
            },
            "payment_preparation": {
                "record": "No-op payment preparation record only; no payment sent.",
                "status": "prepared_no_op",
                "step_id": "payment_preparation",
            },
        },
        context={
            "amount": 24800,
            "fictional_case_id": "MV-248",
            "payment_preparation_record": "NO-OP-PAYMENT-MV-248",
            "vendor_id": "M-1042",
        },
        transcript=(
            {
                "speaker": "Accounts-payable lead",
                "text": "Process fictional invoice MV-248 for vendor M-1042.",
            },
            {
                "speaker": "Meridian",
                "text": "Payment preparation was requested before vendor verification.",
            },
        ),
    ),
    ("meridian", "corrected"): ScenarioFixture(
        scenario_id="meridian",
        variant="corrected",
        participant="meridian-invoice-01",
        role="accounts_payable",
        prompt="Process fictional invoice MV-248 through the governed workflow.",
        output={
            "approval": {
                "record": "Fictional approval AP-MV-248 was recorded.",
                "status": "approved",
                "step_id": "approval",
            },
            "invoice_intake": {
                "record": "Fictional invoice MV-248 was received.",
                "status": "recorded",
                "step_id": "invoice_intake",
            },
            "payment_preparation": {
                "record": "No-op payment preparation record only; no payment sent.",
                "status": "prepared_no_op",
                "step_id": "payment_preparation",
            },
            "risk_review": {
                "record": "Fictional review RR-MV-248 was completed.",
                "status": "reviewed",
                "step_id": "risk_review",
            },
            "vendor_verification": {
                "record": "Fictional vendor M-1042 was verified.",
                "status": "verified",
                "step_id": "vendor_verification",
            },
        },
        context={
            "amount": 24800,
            "fictional_case_id": "MV-248",
            "payment_preparation_record": "NO-OP-PAYMENT-MV-248",
            "vendor_id": "M-1042",
        },
        transcript=(
            {
                "speaker": "Accounts-payable lead",
                "text": "Retry invoice MV-248 in the required order.",
            },
            {
                "speaker": "Meridian",
                "text": "All five governed steps and approval are recorded.",
            },
        ),
    ),
}


def get_fixture(scenario_id: str, variant: str) -> ScenarioFixture:
    return SCENARIO_FIXTURES[(scenario_id, variant)]
