"""
Stable public API for the Aegis Governance SDK.
"""

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from aegis.enforcement import (  # noqa: F401
        AEGIS, AIGC, PreCallResult, configure_module_enforcement,
        enforce_invocation, enforce_invocation_async, enforce_post_call,
        enforce_post_call_async, enforce_pre_call, enforce_pre_call_async,
    )
    from aegis.errors import (  # noqa: F401
        AIGCError, ArtifactSigningError, AuditSinkError, ChainLinkError,
        CheckpointError, ConditionResolutionError, CustomGateViolationError,
        EvidenceConfigurationError, EvidenceFinalizationError,
        FeatureNotImplementedError, GovernanceViolationError,
        GuardEvaluationError, InvocationValidationError, PolicyLoadError,
        PolicyValidationError, PreconditionError, RiskThresholdError,
        SchemaValidationError, SessionStateError, SignatureMetadataError,
        SigningContractError, ToolConstraintViolationError,
        VerificationContractError, WorkflowApprovalRequiredError,
        WorkflowHandoffDeniedError, WorkflowHookDeniedError,
        WorkflowParticipantMismatchError, WorkflowProtocolViolationError,
        WorkflowRoleViolationError, WorkflowSequenceViolationError,
        WorkflowSessionTokenInvalidError, WorkflowSourceRequiredError,
        WorkflowStarterIntegrityError, WorkflowStepBudgetExceededError,
        WorkflowToolBudgetExceededError, WorkflowTransitionDeniedError,
        WorkflowUnsupportedBindingError,
    )
    from aegis.session import (  # noqa: F401
        GovernanceSession, SessionPreCallResult,
    )
    from aegis.retry import RetryExhaustedError, with_retry  # noqa: F401
    from aegis.sinks import (  # noqa: F401
        AuditSink, CallbackAuditSink, JsonFileAuditSink, get_audit_sink,
        set_audit_sink,
    )
    from aegis.builder import InvocationBuilder  # noqa: F401
    from aegis.decorators import governed  # noqa: F401
    from aegis.signing import (  # noqa: F401
        AnchorStatus, ArtifactSigner, ArtifactVerificationResult,
        CANONICALIZATION_VERSION, EvidenceType, ExternalArtifactSigner,
        ExternalArtifactVerifier, ExternalVerificationOutcome, HMACSigner,
        SIGNATURE_METADATA_SCHEMA_VERSION, SIGNING_PROFILE,
        SignatureEncoding, SignatureMetadata, SignatureStatus,
        SignerIdentity, SigningReceipt, VerificationReasonCode,
        sign_artifact, sign_artifact_with_metadata, verify_artifact,
        verify_artifact_detailed,
    )
    from aegis.checkpoints import (  # noqa: F401
        CheckpointBindingStatus, CheckpointSignatureStatus,
        CheckpointVerificationResult, TrustedChainCheckpoint,
        TrustedWorkflowCheckpoint, create_chain_checkpoint,
        create_workflow_checkpoint,
    )
    from aegis.gates import (  # noqa: F401
        EnforcementGate, GateResult, INSERTION_POST_AUTHORIZATION,
        INSERTION_POST_OUTPUT, INSERTION_PRE_AUTHORIZATION,
        INSERTION_PRE_OUTPUT,
    )
    from aegis.audit_chain import (  # noqa: F401
        AuditChain, ChainCoordinates, ChainContinuity, ChainLinker,
        ChainLinkRequest, ChainReservation, ChainVerificationReport,
        Completeness, ContentIntegrity, VerificationError, verify_chain,
        verify_chain_detailed,
    )
    from aegis.workflow_verification import (  # noqa: F401
        WorkflowClaimStatus, WorkflowVerificationReport,
        verify_workflow_claim,
    )
    from aegis._internal.evidence_profiles import (  # noqa: F401
        EvidenceProfileError, build_content_checksum_v2,
        verify_content_checksum_v2,
    )
    from aegis._internal.legacy import (  # noqa: F401
        LegacyAuthorization, LegacyFeature, create_legacy_authorization,
    )
    from aegis.lineage import AuditLineage  # noqa: F401
    from aegis.provenance_gate import ProvenanceGate  # noqa: F401
    from aegis.risk_history import (  # noqa: F401
        RiskHistory, TRAJECTORY_DEGRADING, TRAJECTORY_IMPROVING,
        TRAJECTORY_STABLE,
    )
    from aegis.policy_loader import (  # noqa: F401
        COMPOSITION_INTERSECT, COMPOSITION_REPLACE, COMPOSITION_UNION,
        FilePolicyLoader, PolicyLoaderBase, load_policy, merge_policies,
        validate_policy_dates,
    )
    from aegis.risk_scoring import (  # noqa: F401
        RISK_MODE_RISK_SCORED, RISK_MODE_STRICT, RISK_MODE_WARN_ONLY,
        RiskScore, compute_risk_score,
    )
    from aegis.policy_testing import (  # noqa: F401
        PolicyTestCase, PolicyTestResult, PolicyTestSuite, expect_fail,
        expect_pass,
    )

# Resolve from the implementation owners on every execution.  ``reload`` keeps
# a module dictionary, so neither a corrupted private cache nor monkeypatched
# public facade can become the next generation's authority.
from aegis._internal.checkpoint_models import (  # noqa: E402,F401,F811
    CheckpointBindingStatus,
    CheckpointSignatureStatus,
    CheckpointVerificationResult,
    TrustedChainCheckpoint,
    TrustedWorkflowCheckpoint,
)
from aegis._internal.checkpoint_signing import (  # noqa: E402,F401,F811
    create_chain_checkpoint,
    create_workflow_checkpoint,
)
from aegis._internal.errors import CheckpointError  # noqa: E402,F401,F811

_CANONICAL_CHECKPOINT_EXPORTS = (
    ("CheckpointBindingStatus", CheckpointBindingStatus),
    ("CheckpointError", CheckpointError),
    ("CheckpointSignatureStatus", CheckpointSignatureStatus),
    ("CheckpointVerificationResult", CheckpointVerificationResult),
    ("TrustedChainCheckpoint", TrustedChainCheckpoint),
    ("TrustedWorkflowCheckpoint", TrustedWorkflowCheckpoint),
    ("create_chain_checkpoint", create_chain_checkpoint),
    ("create_workflow_checkpoint", create_workflow_checkpoint),
)

(
    (_, CheckpointBindingStatus),
    (_, CheckpointError),
    (_, CheckpointSignatureStatus),
    (_, CheckpointVerificationResult),
    (_, TrustedChainCheckpoint),
    (_, TrustedWorkflowCheckpoint),
    (_, create_chain_checkpoint),
    (_, create_workflow_checkpoint),
) = _CANONICAL_CHECKPOINT_EXPORTS

_EXPORT_GROUPS = (
    ("aegis.enforcement", (
        "AEGIS", "AIGC", "configure_module_enforcement", "PreCallResult",
        "enforce_invocation", "enforce_invocation_async", "enforce_post_call",
        "enforce_post_call_async", "enforce_pre_call", "enforce_pre_call_async",
    )),
    ("aegis.errors", (
        "AIGCError", "ArtifactSigningError", "AuditSinkError", "ChainLinkError",
        "CheckpointError", "ConditionResolutionError", "CustomGateViolationError",
        "EvidenceConfigurationError", "EvidenceFinalizationError",
        "FeatureNotImplementedError", "GovernanceViolationError",
        "GuardEvaluationError", "InvocationValidationError", "PolicyLoadError",
        "PolicyValidationError", "PreconditionError", "RiskThresholdError",
        "SchemaValidationError", "SessionStateError", "SignatureMetadataError",
        "SigningContractError", "ToolConstraintViolationError",
        "VerificationContractError", "WorkflowApprovalRequiredError",
        "WorkflowHandoffDeniedError", "WorkflowHookDeniedError",
        "WorkflowParticipantMismatchError", "WorkflowProtocolViolationError",
        "WorkflowRoleViolationError", "WorkflowSequenceViolationError",
        "WorkflowSessionTokenInvalidError", "WorkflowSourceRequiredError",
        "WorkflowStarterIntegrityError", "WorkflowStepBudgetExceededError",
        "WorkflowToolBudgetExceededError", "WorkflowTransitionDeniedError",
        "WorkflowUnsupportedBindingError",
    )),
    ("aegis.session", ("GovernanceSession", "SessionPreCallResult")),
    ("aegis.retry", ("with_retry", "RetryExhaustedError")),
    ("aegis.sinks", (
        "AuditSink", "CallbackAuditSink", "JsonFileAuditSink",
        "get_audit_sink", "set_audit_sink",
    )),
    ("aegis.builder", ("InvocationBuilder",)),
    ("aegis.decorators", ("governed",)),
    ("aegis.signing", (
        "AnchorStatus", "ArtifactSigner", "ArtifactVerificationResult",
        "CANONICALIZATION_VERSION", "EvidenceType", "ExternalArtifactSigner",
        "ExternalArtifactVerifier", "ExternalVerificationOutcome", "HMACSigner",
        "SIGNATURE_METADATA_SCHEMA_VERSION", "SIGNING_PROFILE",
        "SignatureEncoding", "SignatureMetadata", "SignatureStatus",
        "SignerIdentity", "SigningReceipt", "VerificationReasonCode",
        "sign_artifact", "sign_artifact_with_metadata", "verify_artifact",
        "verify_artifact_detailed",
    )),
    ("aegis.checkpoints", (
        "CheckpointBindingStatus", "CheckpointSignatureStatus",
        "CheckpointVerificationResult", "TrustedChainCheckpoint",
        "TrustedWorkflowCheckpoint", "create_chain_checkpoint",
        "create_workflow_checkpoint",
    )),
    ("aegis.gates", (
        "EnforcementGate", "GateResult", "INSERTION_PRE_AUTHORIZATION",
        "INSERTION_POST_AUTHORIZATION", "INSERTION_PRE_OUTPUT",
        "INSERTION_POST_OUTPUT",
    )),
    ("aegis.audit_chain", (
        "AuditChain", "ChainCoordinates", "ChainContinuity", "ChainLinker",
        "ChainLinkRequest", "ChainReservation", "ChainVerificationReport",
        "Completeness", "ContentIntegrity", "VerificationError", "verify_chain",
        "verify_chain_detailed",
    )),
    ("aegis.workflow_verification", (
        "WorkflowClaimStatus", "WorkflowVerificationReport",
        "verify_workflow_claim",
    )),
    ("aegis._internal.evidence_profiles", (
        "EvidenceProfileError", "build_content_checksum_v2",
        "verify_content_checksum_v2",
    )),
    ("aegis._internal.legacy", (
        "LegacyAuthorization", "LegacyFeature", "create_legacy_authorization",
    )),
    ("aegis.lineage", ("AuditLineage",)),
    ("aegis.provenance_gate", ("ProvenanceGate",)),
    ("aegis.risk_history", (
        "RiskHistory", "TRAJECTORY_DEGRADING", "TRAJECTORY_IMPROVING",
        "TRAJECTORY_STABLE",
    )),
    ("aegis.policy_loader", (
        "PolicyLoaderBase", "FilePolicyLoader", "load_policy", "merge_policies",
        "validate_policy_dates", "COMPOSITION_INTERSECT", "COMPOSITION_UNION",
        "COMPOSITION_REPLACE",
    )),
    ("aegis.risk_scoring", (
        "compute_risk_score", "RiskScore", "RISK_MODE_STRICT",
        "RISK_MODE_RISK_SCORED", "RISK_MODE_WARN_ONLY",
    )),
    ("aegis.policy_testing", (
        "PolicyTestCase", "PolicyTestResult", "PolicyTestSuite", "expect_pass",
        "expect_fail",
    )),
)

# ``importlib.reload`` retains a module dictionary.  Remove any legacy lazy
# value installed by callers or an earlier implementation before resolving it
# from its source module again.
for _module_name, _exported_names in _EXPORT_GROUPS:
    if _module_name != "aegis.checkpoints":
        for _exported_name in _exported_names:
            globals().pop(_exported_name, None)


def __getattr__(name: str) -> object:
    """Resolve one stable public export without eagerly importing the SDK."""
    for canonical_name, canonical_value in _CANONICAL_CHECKPOINT_EXPORTS:
        if name == canonical_name:
            globals()[name] = canonical_value
            return canonical_value
    for module_name, exported_names in _EXPORT_GROUPS:
        if name in exported_names:
            module = __import__(module_name, fromlist=(name,))
            return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """Expose lazy public names to interactive discovery."""
    return sorted((*globals(), *__all__))


__version__ = "0.9.0b1"

__all__ = [
    "AEGIS",
    "AIGC",
    "AIGCError",
    "AnchorStatus",
    "GovernanceSession",
    "PreCallResult",
    "SessionPreCallResult",
    "SessionStateError",
    "ArtifactSigner",
    "ArtifactSigningError",
    "ArtifactVerificationResult",
    "AuditChain",
    "ChainCoordinates",
    "ChainContinuity",
    "ChainLinkError",
    "ChainLinker",
    "ChainLinkRequest",
    "ChainReservation",
    "ChainVerificationReport",
    "CheckpointBindingStatus",
    "CheckpointError",
    "CheckpointSignatureStatus",
    "CheckpointVerificationResult",
    "AuditLineage",
    "AuditSink",
    "AuditSinkError",
    "COMPOSITION_INTERSECT",
    "COMPOSITION_REPLACE",
    "COMPOSITION_UNION",
    "CallbackAuditSink",
    "CANONICALIZATION_VERSION",
    "ConditionResolutionError",
    "Completeness",
    "ContentIntegrity",
    "CustomGateViolationError",
    "EvidenceConfigurationError",
    "EvidenceFinalizationError",
    "EnforcementGate",
    "EvidenceType",
    "EvidenceProfileError",
    "ExternalArtifactSigner",
    "ExternalArtifactVerifier",
    "ExternalVerificationOutcome",
    "FeatureNotImplementedError",
    "FilePolicyLoader",
    "GateResult",
    "GovernanceViolationError",
    "GuardEvaluationError",
    "HMACSigner",
    "INSERTION_POST_AUTHORIZATION",
    "INSERTION_POST_OUTPUT",
    "INSERTION_PRE_AUTHORIZATION",
    "INSERTION_PRE_OUTPUT",
    "InvocationBuilder",
    "InvocationValidationError",
    "JsonFileAuditSink",
    "LegacyAuthorization",
    "LegacyFeature",
    "PolicyLoadError",
    "PolicyLoaderBase",
    "PolicyTestCase",
    "PolicyTestResult",
    "PolicyTestSuite",
    "PolicyValidationError",
    "ProvenanceGate",
    "PreconditionError",
    "RISK_MODE_RISK_SCORED",
    "RISK_MODE_STRICT",
    "RISK_MODE_WARN_ONLY",
    "RetryExhaustedError",
    "RiskHistory",
    "RiskScore",
    "RiskThresholdError",
    "SchemaValidationError",
    "SIGNATURE_METADATA_SCHEMA_VERSION",
    "SIGNING_PROFILE",
    "ToolConstraintViolationError",
    "TrustedChainCheckpoint",
    "TrustedWorkflowCheckpoint",
    "SignatureEncoding",
    "SignatureMetadata",
    "SignatureMetadataError",
    "SignatureStatus",
    "SignerIdentity",
    "SigningContractError",
    "SigningReceipt",
    "VerificationContractError",
    "VerificationError",
    "VerificationReasonCode",
    "WorkflowApprovalRequiredError",
    "WorkflowClaimStatus",
    "WorkflowHandoffDeniedError",
    "WorkflowHookDeniedError",
    "WorkflowParticipantMismatchError",
    "WorkflowProtocolViolationError",
    "WorkflowRoleViolationError",
    "WorkflowSequenceViolationError",
    "WorkflowSessionTokenInvalidError",
    "WorkflowSourceRequiredError",
    "WorkflowStarterIntegrityError",
    "WorkflowStepBudgetExceededError",
    "WorkflowToolBudgetExceededError",
    "WorkflowTransitionDeniedError",
    "WorkflowUnsupportedBindingError",
    "WorkflowVerificationReport",
    "TRAJECTORY_DEGRADING",
    "TRAJECTORY_IMPROVING",
    "TRAJECTORY_STABLE",
    "compute_risk_score",
    "create_chain_checkpoint",
    "create_legacy_authorization",
    "create_workflow_checkpoint",
    "configure_module_enforcement",
    "enforce_invocation",
    "enforce_invocation_async",
    "enforce_post_call",
    "enforce_post_call_async",
    "enforce_pre_call",
    "enforce_pre_call_async",
    "expect_fail",
    "build_content_checksum_v2",
    "expect_pass",
    "get_audit_sink",
    "governed",
    "load_policy",
    "merge_policies",
    "set_audit_sink",
    "sign_artifact",
    "sign_artifact_with_metadata",
    "validate_policy_dates",
    "verify_artifact",
    "verify_artifact_detailed",
    "verify_chain",
    "verify_chain_detailed",
    "verify_content_checksum_v2",
    "verify_workflow_claim",
    "with_retry",
]
