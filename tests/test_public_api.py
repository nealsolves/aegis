import aegis
from aegis import __version__, AEGIS, AIGC
from aegis.enforcement import enforce_invocation
from aegis.errors import (
    AIGCError,
    AuditSinkError,
    ConditionResolutionError,
    FeatureNotImplementedError,
    GovernanceViolationError,
    GuardEvaluationError,
    InvocationValidationError,
    PolicyLoadError,
    PolicyValidationError,
    PreconditionError,
    SchemaValidationError,
    ToolConstraintViolationError,
    WorkflowHandoffDeniedError,
    WorkflowHookDeniedError,
    WorkflowParticipantMismatchError,
    WorkflowProtocolViolationError,
    WorkflowRoleViolationError,
    WorkflowSequenceViolationError,
    WorkflowStepBudgetExceededError,
    WorkflowTransitionDeniedError,
)
from aegis.sinks import (
    AuditSink,
    CallbackAuditSink,
    JsonFileAuditSink,
    get_audit_sink,
    set_audit_sink,
)


def test_sink_classes_and_functions_exported():
    """Sink classes and management functions are importable from aegis.sinks."""
    assert AuditSink is not None
    assert CallbackAuditSink is not None
    assert JsonFileAuditSink is not None
    assert callable(get_audit_sink)
    assert callable(set_audit_sink)


def test_public_api_imports():
    assert callable(enforce_invocation)
    assert __version__ == "0.9.0b1"
    assert InvocationValidationError.__name__ == "InvocationValidationError"


def test_aegis_class_exported():
    assert AEGIS is not None
    assert callable(AEGIS)


def test_aigc_alias_exported():
    assert AIGC is not None
    assert callable(AIGC)


def test_aegis_aliases_aigc():
    assert AEGIS is AIGC


def test_all_error_types_exported():
    """All error taxonomy types are importable from aegis.errors."""
    for cls in (
        AIGCError,
        AuditSinkError,
        ConditionResolutionError,
        FeatureNotImplementedError,
        GovernanceViolationError,
        GuardEvaluationError,
        InvocationValidationError,
        PolicyLoadError,
        PolicyValidationError,
        PreconditionError,
        SchemaValidationError,
        ToolConstraintViolationError,
    ):
        assert issubclass(cls, AIGCError), f"{cls.__name__} not subclass of AIGCError"


def test_mutable_sink_failure_mode_is_not_a_v2_public_api():
    import aegis.sinks as sinks

    assert "set_sink_failure_mode" not in sinks.__all__
    assert "get_sink_failure_mode" not in sinks.__all__
    assert not hasattr(sinks, "set_sink_failure_mode")
    assert not hasattr(sinks, "get_sink_failure_mode")


def test_top_level_reexports_match_errors_module():
    """All error types are also importable from top-level aegis package."""
    for name in (
        "AuditSinkError",
        "ConditionResolutionError",
        "GuardEvaluationError",
        "ToolConstraintViolationError",
    ):
        assert hasattr(aegis, name), f"aegis.{name} not exported"


def test_top_level_does_not_reexport_mutable_sink_failure_mode():
    assert not hasattr(aegis, "set_sink_failure_mode")
    assert not hasattr(aegis, "get_sink_failure_mode")


def test_m2_risk_scoring_exports():
    """Risk scoring symbols are importable from top-level aegis package."""
    from aegis import (
        compute_risk_score,
        RiskScore,
        RISK_MODE_STRICT,
        RISK_MODE_RISK_SCORED,
        RISK_MODE_WARN_ONLY,
    )
    assert callable(compute_risk_score)
    assert RiskScore is not None
    assert isinstance(RISK_MODE_STRICT, str)
    assert isinstance(RISK_MODE_RISK_SCORED, str)
    assert isinstance(RISK_MODE_WARN_ONLY, str)


def test_m2_signing_exports():
    """Signing functions are importable from top-level aegis package."""
    from aegis import sign_artifact, verify_artifact
    assert callable(sign_artifact)
    assert callable(verify_artifact)


def test_m2_policy_testing_exports():
    """Policy testing framework is importable from top-level aegis package."""
    from aegis import (
        PolicyTestCase,
        PolicyTestResult,
        PolicyTestSuite,
        expect_pass,
        expect_fail,
    )
    assert PolicyTestCase is not None
    assert PolicyTestResult is not None
    assert PolicyTestSuite is not None
    assert callable(expect_pass)
    assert callable(expect_fail)


def test_m2_audit_chain_exports():
    """Audit chain symbols are importable from top-level aegis package."""
    from aegis import AuditChain, verify_chain
    assert AuditChain is not None
    assert callable(verify_chain)


def test_typed_chain_verification_exports():
    from aegis import (
        ChainContinuity,
        ChainVerificationReport,
        Completeness,
        ContentIntegrity,
        VerificationError,
        verify_chain_detailed,
    )

    assert callable(verify_chain_detailed)
    assert ChainVerificationReport is not None
    assert VerificationError is not None
    assert ContentIntegrity.VALID.value == "valid"
    assert ChainContinuity.UNCHAINED.value == "unchained"
    assert Completeness.UNPROVEN.value == "unproven"


def test_audit_lineage_exports():
    """AuditLineage is importable from the top-level aegis package."""
    from aegis import AuditLineage
    assert AuditLineage is not None
    lineage = AuditLineage()
    assert len(lineage) == 0
    assert callable(lineage.from_jsonl)
    assert callable(lineage.checksum_of)


def test_risk_history_exports():
    """RiskHistory and trajectory constants are importable from top-level aegis package."""
    from aegis import (
        RiskHistory,
        TRAJECTORY_IMPROVING,
        TRAJECTORY_STABLE,
        TRAJECTORY_DEGRADING,
    )
    assert callable(RiskHistory)
    assert isinstance(TRAJECTORY_IMPROVING, str)
    assert isinstance(TRAJECTORY_STABLE, str)
    assert isinstance(TRAJECTORY_DEGRADING, str)
    # Smoke: instantiate and use via public import path
    h = RiskHistory("smoke")
    h.record(0.8)
    h.record(0.3)
    assert h.trajectory() == TRAJECTORY_IMPROVING


def test_m2_policy_loader_exports():
    """Policy loader functions and constants importable from top-level aegis package."""
    from aegis import (
        load_policy,
        merge_policies,
        validate_policy_dates,
        COMPOSITION_INTERSECT,
        COMPOSITION_UNION,
        COMPOSITION_REPLACE,
    )
    assert callable(load_policy)
    assert callable(merge_policies)
    assert callable(validate_policy_dates)
    assert isinstance(COMPOSITION_INTERSECT, str)
    assert isinstance(COMPOSITION_UNION, str)
    assert isinstance(COMPOSITION_REPLACE, str)


def test_m2_gate_insertion_point_exports():
    """Gate insertion point constants importable from top-level aegis package."""
    from aegis import (
        INSERTION_PRE_AUTHORIZATION,
        INSERTION_POST_AUTHORIZATION,
        INSERTION_PRE_OUTPUT,
        INSERTION_POST_OUTPUT,
    )
    assert isinstance(INSERTION_PRE_AUTHORIZATION, str)
    assert isinstance(INSERTION_POST_AUTHORIZATION, str)
    assert isinstance(INSERTION_PRE_OUTPUT, str)
    assert isinstance(INSERTION_POST_OUTPUT, str)


def test_audit_reexport_stub():
    """All symbols in aegis.audit are importable from the public path."""
    from aegis.audit import (
        AUDIT_SCHEMA_VERSION,
        POLICY_SCHEMA_VERSION,
        checksum,
        generate_audit_artifact,
    )
    assert isinstance(AUDIT_SCHEMA_VERSION, str)
    assert isinstance(POLICY_SCHEMA_VERSION, str)
    assert callable(checksum)
    assert callable(generate_audit_artifact)


def test_validator_reexport_stub():
    """All symbols in aegis.validator are importable from the public path."""
    from aegis.validator import (
        validate_postconditions,
        validate_preconditions,
        validate_role,
        validate_schema,
    )
    assert callable(validate_postconditions)
    assert callable(validate_preconditions)
    assert callable(validate_role)
    assert callable(validate_schema)


def test_workflow_trace_reexport_stub():
    """workflow trace utilities are importable from the public path."""
    from aegis.workflow_trace import reconstruct_trace

    assert callable(reconstruct_trace)


def test_workflow_export_reexport_stub():
    """workflow export utilities are importable from the public path."""
    from aegis.workflow_export import export_workflow

    assert callable(export_workflow)


def test_telemetry_reexport_stub():
    """aegis.telemetry re-export is importable from the public path."""
    from aegis.telemetry import is_otel_available
    assert callable(is_otel_available)


def test_split_enforcement_exports():
    """Split enforcement symbols are importable from top-level aegis package."""
    from aegis import (
        PreCallResult,
        enforce_pre_call,
        enforce_post_call,
        enforce_pre_call_async,
        enforce_post_call_async,
    )
    assert PreCallResult is not None
    assert callable(enforce_pre_call)
    assert callable(enforce_post_call)
    assert callable(enforce_pre_call_async)
    assert callable(enforce_post_call_async)


def test_split_enforcement_top_level_hasattr():
    """Split enforcement symbols accessible via hasattr on aegis."""
    for name in (
        "PreCallResult",
        "enforce_pre_call",
        "enforce_post_call",
        "enforce_pre_call_async",
        "enforce_post_call_async",
    ):
        assert hasattr(aegis, name), f"aegis.{name} not exported"


def test_pr06_workflow_error_classes_exported():
    """All PR-06 frozen reason-code error classes are importable from aegis."""
    from aegis import (
        WorkflowApprovalRequiredError,
        WorkflowSourceRequiredError,
        WorkflowToolBudgetExceededError,
        WorkflowUnsupportedBindingError,
        WorkflowSessionTokenInvalidError,
    )
    from aegis import AIGCError, GovernanceViolationError

    assert WorkflowApprovalRequiredError is not None
    assert issubclass(WorkflowApprovalRequiredError, GovernanceViolationError)

    assert WorkflowSourceRequiredError is not None
    assert issubclass(WorkflowSourceRequiredError, GovernanceViolationError)

    assert WorkflowToolBudgetExceededError is not None
    assert issubclass(WorkflowToolBudgetExceededError, GovernanceViolationError)

    assert WorkflowUnsupportedBindingError is not None
    assert issubclass(WorkflowUnsupportedBindingError, GovernanceViolationError)

    assert WorkflowSessionTokenInvalidError is not None
    assert issubclass(WorkflowSessionTokenInvalidError, AIGCError)
    assert not issubclass(WorkflowSessionTokenInvalidError, GovernanceViolationError)


def test_pr06_workflow_errors_in_all():
    """PR-06 error classes are in aegis.__all__."""
    import aegis
    for name in (
        "WorkflowApprovalRequiredError",
        "WorkflowSourceRequiredError",
        "WorkflowToolBudgetExceededError",
        "WorkflowUnsupportedBindingError",
        "WorkflowSessionTokenInvalidError",
    ):
        assert name in aegis.__all__, f"{name} missing from aegis.__all__"


def test_pr06_workflow_errors_have_correct_codes():
    """Each PR-06 error class carries the frozen reason code."""
    from aegis import (
        WorkflowApprovalRequiredError,
        WorkflowSourceRequiredError,
        WorkflowToolBudgetExceededError,
        WorkflowUnsupportedBindingError,
        WorkflowSessionTokenInvalidError,
    )
    assert WorkflowApprovalRequiredError("x").code == "WORKFLOW_APPROVAL_REQUIRED"
    assert WorkflowSourceRequiredError("x").code == "WORKFLOW_SOURCE_REQUIRED"
    assert WorkflowToolBudgetExceededError("x").code == "WORKFLOW_TOOL_BUDGET_EXCEEDED"
    assert WorkflowUnsupportedBindingError("x").code == "WORKFLOW_UNSUPPORTED_BINDING"
    assert WorkflowSessionTokenInvalidError("x").code == "WORKFLOW_SESSION_TOKEN_INVALID"


def test_pr08_public_workflow_errors_exported():
    """Workflow-step errors raised by public session methods must be publicly importable."""
    for cls in (
        WorkflowParticipantMismatchError,
        WorkflowSequenceViolationError,
        WorkflowTransitionDeniedError,
        WorkflowRoleViolationError,
        WorkflowProtocolViolationError,
        WorkflowHandoffDeniedError,
        WorkflowStepBudgetExceededError,
        WorkflowHookDeniedError,
    ):
        assert issubclass(cls, AIGCError), f"{cls.__name__} not subclass of AIGCError"
        assert hasattr(aegis, cls.__name__), f"aegis.{cls.__name__} not exported"
        assert cls.__name__ in aegis.__all__, f"{cls.__name__} missing from aegis.__all__"


def test_all_list_completeness():
    """__all__ contains every M2 symbol that should be public."""
    expected_m2_symbols = {
        "compute_risk_score", "RiskScore",
        "RISK_MODE_STRICT", "RISK_MODE_RISK_SCORED", "RISK_MODE_WARN_ONLY",
        "sign_artifact", "verify_artifact",
        "PolicyTestCase", "PolicyTestResult", "PolicyTestSuite",
        "expect_pass", "expect_fail",
        "AuditLineage",
        "verify_chain",
        "load_policy", "merge_policies", "validate_policy_dates",
        "COMPOSITION_INTERSECT", "COMPOSITION_UNION", "COMPOSITION_REPLACE",
        "INSERTION_PRE_AUTHORIZATION", "INSERTION_POST_AUTHORIZATION",
        "INSERTION_PRE_OUTPUT", "INSERTION_POST_OUTPUT",
        "RiskHistory",
        "TRAJECTORY_IMPROVING",
        "TRAJECTORY_STABLE",
        "TRAJECTORY_DEGRADING",
    }
    all_set = set(aegis.__all__)
    missing = expected_m2_symbols - all_set
    assert not missing, f"Missing from __all__: {sorted(missing)}"


def test_kms_integration_contract_stays_out_of_existing_public_namespaces():
    """KMS adapters are opt-in modules, not additions to the core signing API."""
    import aegis.signing as signing_module

    forbidden = {
        "KmsKeyDisposition",
        "AwsKmsArtifactSigner",
        "AwsKmsArtifactVerifier",
        "AwsKmsVerificationTarget",
        "GoogleCloudKmsArtifactSigner",
        "GoogleCloudKmsArtifactVerifier",
        "GoogleCloudKmsVerificationTarget",
    }

    assert forbidden.isdisjoint(aegis.__all__)
    assert forbidden.isdisjoint(signing_module.__all__)


def test_trust_anchor_signing_contracts_are_public_and_identical():
    """Trust-anchor contracts have explicit module and package import paths."""
    import aegis.signing as signing_module
    from aegis.signing import (
        ArtifactSigner as signing_ArtifactSigner,
        HMACSigner as signing_HMACSigner,
        sign_artifact as signing_sign_artifact,
        verify_artifact as signing_verify_artifact,
        SIGNATURE_METADATA_SCHEMA_VERSION as signing_metadata_schema_version,
        SIGNING_PROFILE as signing_profile,
        CANONICALIZATION_VERSION as signing_canonicalization_version,
        EvidenceType as signing_EvidenceType,
        SignatureEncoding as signing_SignatureEncoding,
        SignatureStatus as signing_SignatureStatus,
        AnchorStatus as signing_AnchorStatus,
        VerificationReasonCode as signing_VerificationReasonCode,
        SignerIdentity as signing_SignerIdentity,
        SignatureMetadata as signing_SignatureMetadata,
        SigningReceipt as signing_SigningReceipt,
        ExternalVerificationOutcome as signing_ExternalVerificationOutcome,
        ArtifactVerificationResult as signing_ArtifactVerificationResult,
        ExternalArtifactSigner as signing_ExternalArtifactSigner,
        ExternalArtifactVerifier as signing_ExternalArtifactVerifier,
        sign_artifact_with_metadata as signing_sign_artifact_with_metadata,
        verify_artifact_detailed as signing_verify_artifact_detailed,
    )
    from aegis import (
        ArtifactSigner as top_ArtifactSigner,
        HMACSigner as top_HMACSigner,
        sign_artifact as top_sign_artifact,
        verify_artifact as top_verify_artifact,
        SIGNATURE_METADATA_SCHEMA_VERSION as top_metadata_schema_version,
        SIGNING_PROFILE as top_signing_profile,
        CANONICALIZATION_VERSION as top_canonicalization_version,
        EvidenceType as top_EvidenceType,
        SignatureEncoding as top_SignatureEncoding,
        SignatureStatus as top_SignatureStatus,
        AnchorStatus as top_AnchorStatus,
        VerificationReasonCode as top_VerificationReasonCode,
        SignerIdentity as top_SignerIdentity,
        SignatureMetadata as top_SignatureMetadata,
        SigningReceipt as top_SigningReceipt,
        ExternalVerificationOutcome as top_ExternalVerificationOutcome,
        ArtifactVerificationResult as top_ArtifactVerificationResult,
        ExternalArtifactSigner as top_ExternalArtifactSigner,
        ExternalArtifactVerifier as top_ExternalArtifactVerifier,
        sign_artifact_with_metadata as top_sign_artifact_with_metadata,
        verify_artifact_detailed as top_verify_artifact_detailed,
    )

    module_exports = (
        signing_ArtifactSigner,
        signing_HMACSigner,
        signing_sign_artifact,
        signing_verify_artifact,
        signing_metadata_schema_version,
        signing_profile,
        signing_canonicalization_version,
        signing_EvidenceType,
        signing_SignatureEncoding,
        signing_SignatureStatus,
        signing_AnchorStatus,
        signing_VerificationReasonCode,
        signing_SignerIdentity,
        signing_SignatureMetadata,
        signing_SigningReceipt,
        signing_ExternalVerificationOutcome,
        signing_ArtifactVerificationResult,
        signing_ExternalArtifactSigner,
        signing_ExternalArtifactVerifier,
        signing_sign_artifact_with_metadata,
        signing_verify_artifact_detailed,
    )
    top_level_exports = (
        top_ArtifactSigner,
        top_HMACSigner,
        top_sign_artifact,
        top_verify_artifact,
        top_metadata_schema_version,
        top_signing_profile,
        top_canonicalization_version,
        top_EvidenceType,
        top_SignatureEncoding,
        top_SignatureStatus,
        top_AnchorStatus,
        top_VerificationReasonCode,
        top_SignerIdentity,
        top_SignatureMetadata,
        top_SigningReceipt,
        top_ExternalVerificationOutcome,
        top_ArtifactVerificationResult,
        top_ExternalArtifactSigner,
        top_ExternalArtifactVerifier,
        top_sign_artifact_with_metadata,
        top_verify_artifact_detailed,
    )
    expected_names = {
        "ArtifactSigner",
        "HMACSigner",
        "sign_artifact",
        "verify_artifact",
        "SIGNATURE_METADATA_SCHEMA_VERSION",
        "SIGNING_PROFILE",
        "CANONICALIZATION_VERSION",
        "EvidenceType",
        "SignatureEncoding",
        "SignatureStatus",
        "AnchorStatus",
        "VerificationReasonCode",
        "SignerIdentity",
        "SignatureMetadata",
        "SigningReceipt",
        "ExternalVerificationOutcome",
        "ArtifactVerificationResult",
        "ExternalArtifactSigner",
        "ExternalArtifactVerifier",
        "sign_artifact_with_metadata",
        "verify_artifact_detailed",
    }

    assert all(top is module for top, module in zip(top_level_exports, module_exports))
    assert expected_names <= set(signing_module.__all__)
    assert expected_names <= set(aegis.__all__)


def test_trust_anchor_errors_are_public_and_identical():
    """Signing error contracts have explicit module and package import paths."""
    import aegis.errors as errors_module
    from aegis.errors import (
        ArtifactSigningError as errors_ArtifactSigningError,
        SignatureMetadataError as errors_SignatureMetadataError,
        SigningContractError as errors_SigningContractError,
        VerificationContractError as errors_VerificationContractError,
    )
    from aegis import (
        ArtifactSigningError as top_ArtifactSigningError,
        SignatureMetadataError as top_SignatureMetadataError,
        SigningContractError as top_SigningContractError,
        VerificationContractError as top_VerificationContractError,
    )

    module_exports = (
        errors_ArtifactSigningError,
        errors_SignatureMetadataError,
        errors_SigningContractError,
        errors_VerificationContractError,
    )
    top_level_exports = (
        top_ArtifactSigningError,
        top_SignatureMetadataError,
        top_SigningContractError,
        top_VerificationContractError,
    )
    expected_names = {
        "ArtifactSigningError",
        "SignatureMetadataError",
        "SigningContractError",
        "VerificationContractError",
    }

    assert all(top is module for top, module in zip(top_level_exports, module_exports))
    assert all(issubclass(error, AIGCError) for error in module_exports)
    assert expected_names <= set(errors_module.__all__)
    assert expected_names <= set(aegis.__all__)


def test_trusted_checkpoint_names_are_in_the_top_level_all_contract():
    expected_names = {
        "CheckpointBindingStatus",
        "CheckpointError",
        "CheckpointSignatureStatus",
        "CheckpointVerificationResult",
        "TrustedChainCheckpoint",
        "TrustedWorkflowCheckpoint",
        "create_chain_checkpoint",
        "create_workflow_checkpoint",
    }

    assert expected_names <= set(aegis.__all__)
