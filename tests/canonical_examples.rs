//! Canonical examples round-trip witness.
//!
//! Parses `examples/canonical.nota` end-to-end, decoding each record
//! through its NOTA codec and asserting the re-encoded text equals
//! the canonical form. The selection covers the Path A lifecycle
//! and one example per request/reply family. Exhaustive per-variant
//! round-trip witnesses already live in `tests/round_trip.rs`.

use nota_next::{NotaDecode, NotaEncode, NotaSource};
use signal_criome::{
    ArchiveAttestationRequest, Attestation, AttestationReceipt, AttestedMoment,
    AttestedMomentProposition, AuditContext, AuthorizationAttestationRequest, AuthorizationDenial,
    AuthorizationDenialReason, AuthorizationDenialSource, AuthorizationDenied,
    AuthorizationEvaluated, AuthorizationEvaluation, AuthorizationExpired, AuthorizationGrant,
    AuthorizationObservation, AuthorizationObservationRetracted, AuthorizationObservationSnapshot,
    AuthorizationObservationToken, AuthorizationPending, AuthorizationPolicyClass,
    AuthorizationPolicySatisfaction, AuthorizationRejection, AuthorizationRequestSlot,
    AuthorizationScope, AuthorizationStateRecord, AuthorizationStatus, AuthorizationUnavailable,
    AuthorizationUpdate, AuthorizationVerification, BlsPublicKey, BlsSignature,
    ChannelGrantAttestationRequest, ComponentRelease, ContentPurpose, ContentReference, Contract,
    ContractAdmissionRejected, ContractAdmissionRejectionReason, ContractAdmitted, ContractDigest,
    ContractFound, ContractMissing, ContractName, ContractOperationHead, CriomeEvent, CriomeReply,
    CriomeRequest, EvaluationDecision, EvaluationRejectionReason, Evidence, Identity,
    IdentityLookup, IdentityReceipt, IdentityRegistration, IdentityRevocation, IdentitySnapshot,
    IdentitySubscription, IdentitySubscriptionToken, IdentityUpdate, KeyPurpose, ObjectDigest,
    OperationDigest, PolicyMember, PrincipalName, PrincipalStatus, PublicKeyFingerprint,
    QuorumShortfall, Rejection, RejectionReason, ReplayNonce, RequiredSignatureThreshold, Rule,
    SignReceipt, SignRequest, SignalCallAuthorization, SignatureAuthorizationResult,
    SignatureEnvelope, SignatureRouteReceipt, SignatureScheme, SignatureSolicitation,
    SignatureSolicitationRoute, SignatureSubmission, SignatureSubmissionReceipt,
    SubscriptionRetracted, Threshold, TimeSignature, TimeWindow, TimestampNanos,
    VerificationDecision, VerificationResult, VerifyRequest,
};

const CANONICAL: &str = include_str!("../examples/canonical.nota");

fn alice() -> Identity {
    Identity::Persona(PrincipalName::new("alice"))
}

fn content_reference() -> ContentReference {
    ContentReference {
        digest: ObjectDigest::new("digest-abc"),
        purpose: ContentPurpose::SignedObject,
        schema_version: PrincipalName::new("schema-1"),
    }
}

fn audit_context() -> AuditContext {
    AuditContext {
        purpose: ContentPurpose::SignedObject,
        audience: PrincipalName::new("audience-bob"),
        policy_version: PrincipalName::new("policy-1"),
        nonce: ReplayNonce::new("nonce-7"),
    }
}

fn envelope() -> SignatureEnvelope {
    SignatureEnvelope {
        scheme: SignatureScheme::Bls12_381MinPk,
        public_key: BlsPublicKey::new("public-key-1"),
        signature: BlsSignature::new("signature-1"),
    }
}

fn attestation() -> Attestation {
    Attestation {
        content: content_reference(),
        signer: alice(),
        envelope: envelope(),
        issued_at: TimestampNanos::new(100),
        expires_at: None,
        audit_context: audit_context(),
    }
}

fn token() -> IdentitySubscriptionToken {
    IdentitySubscriptionToken::new(alice())
}

fn authorization_request_slot() -> AuthorizationRequestSlot {
    AuthorizationRequestSlot::new("authorization-request-1")
}

fn authorization_observation_token() -> AuthorizationObservationToken {
    AuthorizationObservationToken::new(authorization_request_slot())
}

fn contract_name() -> ContractName {
    ContractName::new("signal-lojix")
}

fn contract_operation_head() -> ContractOperationHead {
    ContractOperationHead::new("Deploy")
}

fn authorization_scope() -> AuthorizationScope {
    AuthorizationScope::new("deploy-zeus-full-os")
}

fn authorization_grant() -> AuthorizationGrant {
    AuthorizationGrant {
        request_slot: authorization_request_slot(),
        authorized_object_digest: ObjectDigest::new("digest-lojix-request"),
        authorized_contract: contract_name(),
        authorized_operation: contract_operation_head(),
        authorization_scope: authorization_scope(),
        policy_satisfaction: AuthorizationPolicySatisfaction {
            policy_class: AuthorizationPolicyClass::ComplexQuorum,
            required_signature_threshold: RequiredSignatureThreshold::new(1),
            satisfied_signers: vec![Identity::Cluster(PrincipalName::new("uranus"))],
        },
        signature_result: SignatureAuthorizationResult::RequiredSignaturesSatisfied,
        signatures: vec![envelope()],
        issued_by: Identity::Cluster(PrincipalName::new("uranus")),
        issued_at: TimestampNanos::new(110),
        expires_at: None,
    }
}

fn authorization_state() -> AuthorizationStateRecord {
    AuthorizationStateRecord {
        request_slot: authorization_request_slot(),
        request_digest: ObjectDigest::new("digest-lojix-request"),
        status: AuthorizationStatus::Pending,
        missing_authorities: vec![Identity::Developer(PrincipalName::new("reviewer"))],
        grant: None,
        denial: None,
    }
}

fn signature_solicitation() -> SignatureSolicitation {
    SignatureSolicitation {
        request_slot: authorization_request_slot(),
        request_digest: ObjectDigest::new("digest-lojix-request"),
        contract: contract_name(),
        operation: contract_operation_head(),
        scope: authorization_scope(),
        requester: alice(),
        required_signer: Identity::Developer(PrincipalName::new("reviewer")),
    }
}

fn contract_digest() -> ContractDigest {
    ContractDigest::new(ObjectDigest::new("contract-digest-1"))
}

fn operation_digest() -> OperationDigest {
    OperationDigest::new(ObjectDigest::new("operation-digest-1"))
}

fn attested_moment() -> AttestedMoment {
    AttestedMoment {
        proposition: AttestedMomentProposition {
            window: TimeWindow {
                opens_at: TimestampNanos::new(10),
                closes_at: TimestampNanos::new(20),
            },
            required_signatures: RequiredSignatureThreshold::new(1),
            authorities: vec![Identity::Developer(PrincipalName::new("timekeeper"))],
        },
        signatures: vec![TimeSignature {
            signer: Identity::Developer(PrincipalName::new("timekeeper")),
            envelope: envelope(),
        }],
    }
}

fn policy_contract() -> Contract {
    Contract::new(Rule::threshold(Threshold {
        required_signatures: RequiredSignatureThreshold::new(2),
        members: vec![
            PolicyMember::key_member(Identity::Developer(PrincipalName::new("operator"))),
            PolicyMember::key_member(Identity::Developer(PrincipalName::new("reviewer"))),
        ],
    }))
}

fn evidence() -> Evidence {
    Evidence {
        operation: operation_digest(),
        stamp: attested_moment(),
        signatures: vec![envelope()],
        agreements: Vec::new(),
    }
}

fn round_trip<T>(value: T)
where
    T: NotaEncode + NotaDecode + PartialEq + std::fmt::Debug,
{
    let text = value.to_nota();
    let decoded = NotaSource::new(&text).parse::<T>().expect("decode");
    assert_eq!(decoded, value, "decode for {text}");

    assert!(
        CANONICAL.contains(&text),
        "examples/canonical.nota missing line: {text}",
    );
}

#[test]
fn canonical_request_examples_round_trip() {
    round_trip(CriomeRequest::Sign(SignRequest {
        content: content_reference(),
        signer: alice(),
        audit_context: audit_context(),
        expires_at: None,
    }));
    round_trip(CriomeRequest::VerifyAttestation(VerifyRequest {
        attestation: attestation(),
        content: content_reference(),
    }));
    round_trip(CriomeRequest::RegisterIdentity(IdentityRegistration {
        identity: alice(),
        public_key: BlsPublicKey::new("public-key-1"),
        fingerprint: PublicKeyFingerprint::new("fingerprint-1"),
        purpose: KeyPurpose::PersonaRequest,
        admission: None,
    }));
    round_trip(CriomeRequest::RevokeIdentity(IdentityRevocation {
        identity: alice(),
        fingerprint: PublicKeyFingerprint::new("fingerprint-1"),
        reason: PrincipalName::new("revoked-by-owner"),
    }));
    round_trip(CriomeRequest::LookupIdentity(IdentityLookup::new(alice())));
    round_trip(CriomeRequest::AttestArchive(ArchiveAttestationRequest {
        release: ComponentRelease {
            component: PrincipalName::new("persona-router"),
            artifact: ObjectDigest::new("artifact-1"),
            authorized_by: alice(),
        },
        audit_context: AuditContext {
            purpose: ContentPurpose::Archive,
            audience: PrincipalName::new("audience-archive"),
            policy_version: PrincipalName::new("policy-1"),
            nonce: ReplayNonce::new("nonce-8"),
        },
    }));
    round_trip(CriomeRequest::AttestChannelGrant(
        ChannelGrantAttestationRequest {
            grant_content: ContentReference {
                digest: ObjectDigest::new("digest-grant"),
                purpose: ContentPurpose::ChannelGrant,
                schema_version: PrincipalName::new("schema-1"),
            },
            source: alice(),
            audit_context: AuditContext {
                purpose: ContentPurpose::ChannelGrant,
                audience: PrincipalName::new("audience-bob"),
                policy_version: PrincipalName::new("policy-1"),
                nonce: ReplayNonce::new("nonce-9"),
            },
        },
    ));
    round_trip(CriomeRequest::AttestAuthorization(
        AuthorizationAttestationRequest {
            authorization_content: ContentReference {
                digest: ObjectDigest::new("digest-auth"),
                purpose: ContentPurpose::Authorization,
                schema_version: PrincipalName::new("schema-1"),
            },
            source: alice(),
            audit_context: AuditContext {
                purpose: ContentPurpose::Authorization,
                audience: PrincipalName::new("audience-bob"),
                policy_version: PrincipalName::new("policy-1"),
                nonce: ReplayNonce::new("nonce-10"),
            },
        },
    ));
    round_trip(CriomeRequest::AuthorizeSignalCall(
        SignalCallAuthorization {
            request_digest: ObjectDigest::new("digest-lojix-request"),
            contract: contract_name(),
            operation: contract_operation_head(),
            scope: authorization_scope(),
            requester: alice(),
            nonce: ReplayNonce::new("authorization-nonce-1"),
            expires_at: None,
        },
    ));
    round_trip(CriomeRequest::ObserveAuthorization(
        AuthorizationObservation::new(authorization_request_slot()),
    ));
    round_trip(CriomeRequest::VerifyAuthorization(
        AuthorizationVerification {
            request_digest: ObjectDigest::new("digest-lojix-request"),
            authorization: authorization_grant(),
        },
    ));
    round_trip(CriomeRequest::RouteSignatureRequest(
        SignatureSolicitationRoute {
            solicitation: signature_solicitation(),
            routed_to: Identity::Host(PrincipalName::new("balboa")),
        },
    ));
    round_trip(CriomeRequest::SubmitSignature(SignatureSubmission {
        request_slot: authorization_request_slot(),
        signer: Identity::Developer(PrincipalName::new("reviewer")),
        envelope: envelope(),
    }));
    round_trip(CriomeRequest::RejectAuthorization(AuthorizationRejection {
        request_slot: authorization_request_slot(),
        rejector: Identity::Developer(PrincipalName::new("reviewer")),
        reason: AuthorizationDenialReason::SignatureRejected,
    }));
    round_trip(CriomeRequest::AdmitContract(policy_contract()));
    round_trip(CriomeRequest::LookupContract(contract_digest()));
    round_trip(CriomeRequest::EvaluateAuthorization(
        AuthorizationEvaluation {
            contract: contract_digest(),
            evidence: evidence(),
        },
    ));
    round_trip(CriomeRequest::SubscribeIdentityUpdates(
        IdentitySubscription::new(alice()),
    ));
    round_trip(CriomeRequest::IdentitySubscriptionRetraction(token()));
    round_trip(CriomeRequest::AuthorizationObservationRetraction(
        authorization_observation_token(),
    ));
}

#[test]
fn canonical_reply_examples_round_trip() {
    round_trip(CriomeReply::SignReceipt(SignReceipt {
        attestation: attestation(),
        issued_at: TimestampNanos::new(100),
    }));
    round_trip(CriomeReply::VerificationResult(VerificationResult {
        decision: VerificationDecision::Valid,
        identity: Some(alice()),
        expires_at: None,
    }));
    round_trip(CriomeReply::IdentityReceipt(IdentityReceipt {
        identity: alice(),
        status: PrincipalStatus::Active,
    }));
    round_trip(CriomeReply::IdentitySnapshot(IdentitySnapshot::new(vec![
        IdentityReceipt {
            identity: alice(),
            status: PrincipalStatus::Active,
        },
    ])));
    round_trip(CriomeReply::AttestationReceipt(AttestationReceipt::new(
        attestation(),
    )));
    round_trip(CriomeReply::AuthorizationPending(AuthorizationPending {
        request_slot: authorization_request_slot(),
        request_digest: ObjectDigest::new("digest-lojix-request"),
        missing_authorities: vec![Identity::Developer(PrincipalName::new("reviewer"))],
        observation_token: authorization_observation_token(),
    }));
    round_trip(CriomeReply::AuthorizationGranted(authorization_grant()));
    round_trip(CriomeReply::AuthorizationDenied(AuthorizationDenied {
        request_slot: authorization_request_slot(),
        denial: AuthorizationDenial {
            source: AuthorizationDenialSource::Policy,
            reason: AuthorizationDenialReason::SignatureScopeMismatch,
        },
    }));
    round_trip(CriomeReply::AuthorizationExpired(AuthorizationExpired {
        request_slot: authorization_request_slot(),
        expired_at: TimestampNanos::new(111),
    }));
    round_trip(CriomeReply::AuthorizationUnavailable(
        AuthorizationUnavailable {
            request_slot: authorization_request_slot(),
            reason: PrincipalName::new("criome-peer-unreachable"),
        },
    ));
    round_trip(CriomeReply::AuthorizationObservationSnapshot(
        AuthorizationObservationSnapshot::new(vec![authorization_state()]),
    ));
    round_trip(CriomeReply::SignatureRouteReceipt(SignatureRouteReceipt {
        request_slot: authorization_request_slot(),
        routed_to: Identity::Host(PrincipalName::new("balboa")),
    }));
    round_trip(CriomeReply::SignatureSubmissionReceipt(
        SignatureSubmissionReceipt {
            request_slot: authorization_request_slot(),
            signer: Identity::Developer(PrincipalName::new("reviewer")),
        },
    ));
    round_trip(CriomeReply::ContractAdmitted(ContractAdmitted::new(
        contract_digest(),
    )));
    round_trip(CriomeReply::ContractFound(ContractFound {
        digest: contract_digest(),
        contract: policy_contract(),
    }));
    round_trip(CriomeReply::ContractMissing(ContractMissing::new(
        contract_digest(),
    )));
    round_trip(CriomeReply::ContractAdmissionRejected(
        ContractAdmissionRejected::new(ContractAdmissionRejectionReason::DuplicatePolicyMember),
    ));
    round_trip(CriomeReply::AuthorizationEvaluated(
        AuthorizationEvaluated {
            contract: contract_digest(),
            decision: EvaluationDecision::Rejected(EvaluationRejectionReason::QuorumShort(
                QuorumShortfall {
                    required: RequiredSignatureThreshold::new(2),
                    satisfied: RequiredSignatureThreshold::new(1),
                },
            )),
        },
    ));
    round_trip(CriomeReply::AuthorizationObservationRetracted(
        AuthorizationObservationRetracted::new(authorization_observation_token()),
    ));
    round_trip(CriomeReply::SubscriptionRetracted(
        SubscriptionRetracted::new(token()),
    ));
    round_trip(CriomeReply::Rejection(Rejection::new(
        RejectionReason::UnknownIdentity,
    )));
}

#[test]
fn canonical_event_examples_round_trip() {
    round_trip(CriomeEvent::IdentityUpdate(IdentityUpdate::new(
        IdentityReceipt {
            identity: alice(),
            status: PrincipalStatus::Active,
        },
    )));
    round_trip(CriomeEvent::AuthorizationUpdate(AuthorizationUpdate::new(
        authorization_state(),
    )));
}
