//! Canonical examples round-trip witness.
//!
//! Parses `examples/canonical.nota` end-to-end, decoding each record
//! through its NOTA codec and asserting the re-encoded text equals
//! the canonical form. The selection covers the Path A lifecycle
//! and one example per request/reply family. Exhaustive per-variant
//! round-trip witnesses already live in `tests/round_trip.rs`.

use nota_next::{NotaDecode, NotaEncode, NotaSource};
use signal_criome::{
    AdmissionRejectionReason, ObservationToken, Receipt, RejectionDetail, State, SubscriptionToken,
    Token,
};
use signal_criome::{
    ArchiveAttestationRequest, Attestation, AttestationReceipt, AttestedMoment,
    AttestedMomentProposition, AuditContext, AuthorizationAttestationRequest, AuthorizationDenial,
    AuthorizationDenialReason, AuthorizationDenialSource, AuthorizationDenied,
    AuthorizationEvaluated, AuthorizationEvaluation, AuthorizationExpired, AuthorizationGrant,
    AuthorizationObservation, AuthorizationObservationRetracted, AuthorizationObservationSnapshot,
    AuthorizationObservationToken, AuthorizationPending, AuthorizationPolicyClass,
    AuthorizationPolicySatisfaction, AuthorizationRejection, AuthorizationRequestSlot,
    AuthorizationScope, AuthorizationStateRecord, AuthorizationStatus, AuthorizationUnavailable,
    AuthorizationUpdate, AuthorizationVerification, AuthorizedObjectInterest, AuthorizedObjectKind,
    AuthorizedObjectObservation, AuthorizedObjectReference, AuthorizedObjectUpdate,
    AuthorizedObjectUpdateRetracted, AuthorizedObjectUpdateSnapshot, AuthorizedObjectUpdateToken,
    BlsPublicKey, BlsSignature, ChannelGrantAttestationRequest, ComponentKind, ComponentRelease,
    ContentPurpose, ContentReference, Contract, ContractAdmissionRejected,
    ContractAdmissionRejectionReason, ContractAdmitted, ContractDigest, ContractFound,
    ContractMissing, ContractName, ContractOperationHead, CriomeEvent, CriomeReply, CriomeRequest,
    EvaluationDecision, EvaluationRejectionReason, Evidence, Identity, IdentityLookup,
    IdentityReceipt, IdentityRegistration, IdentityRevocation, IdentitySnapshot,
    IdentitySubscription, IdentitySubscriptionToken, IdentityUpdate, KeyPurpose, ObjectDigest,
    OperationDigest, PolicyMember, PrincipalName, PrincipalStatus, PublicKeyFingerprint,
    QuorumShortfall, Rejection, RejectionReason, ReplayNonce, RequiredSignatureThreshold, Rule,
    SignReceipt, SignRequest, SignalCallAuthorization, SignatureAuthorizationResult,
    SignatureEnvelope, SignatureRouteReceipt, SignatureScheme, SignatureSolicitation,
    SignatureSolicitationRoute, SignatureSubmission, SignatureSubmissionReceipt,
    StampedSignatureEnvelope, SubscriptionRetracted, Threshold, TimeSignature, TimeWindow,
    TimestampNanos, VerificationDecision, VerificationResult, VerifyRequest,
};
use signal_criome::{
    Artifact, Audience, Authorization, AuthorizationContent, AuthorizedBy, CallContract,
    CallOperation, CallScope, ClosesAt, Component, Content, ContractObjectDigest, Decision,
    DenialDetail, DenialReason, DenialSource, Digest, Envelope, EnvelopeSignature, ExpiredAt,
    Fingerprint, GrantContent, Interest, IssuedAt, Kind, Nonce, Object, OpensAt, PolicyVersion,
    PrincipalStatusRole, PublicKey, Purpose, Rejector, Release, ReleaseComponent, RequestDigest,
    RequestSlot, Requester, Required, RequiredSigner, RevocationReason, RoutedTo, Satisfied,
    SchemaVersion, Scheme, Signer, Solicitation, Source, Stamp, StampedSignature, Subscriber,
    UnavailableReason,
};

const CANONICAL: &str = include_str!("../examples/canonical.nota");

fn alice() -> Identity {
    Identity::Persona(PrincipalName::new("alice"))
}

fn content_reference() -> ContentReference {
    ContentReference {
        digest: Digest::new(ObjectDigest::new("digest-abc")),
        purpose: Purpose::new(ContentPurpose::SignedObject),
        schema_version: SchemaVersion::new(PrincipalName::new("schema-1")),
    }
}

fn audit_context() -> AuditContext {
    AuditContext {
        purpose: Purpose::new(ContentPurpose::SignedObject),
        audience: Audience::new(PrincipalName::new("audience-bob")),
        policy_version: PolicyVersion::new(PrincipalName::new("policy-1")),
        nonce: Nonce::new(ReplayNonce::new("nonce-7")),
    }
}

fn envelope() -> SignatureEnvelope {
    SignatureEnvelope {
        scheme: Scheme::new(SignatureScheme::Bls12_381MinPk),
        public_key: PublicKey::new(BlsPublicKey::new("public-key-1")),
        envelope_signature: EnvelopeSignature::new(BlsSignature::new("signature-1")),
    }
}

fn stamped_envelope() -> StampedSignatureEnvelope {
    StampedSignatureEnvelope {
        stamp: Stamp::new(attested_moment()),
        envelope: Envelope::new(envelope()),
    }
}

fn attestation() -> Attestation {
    Attestation::new(
        content_reference(),
        alice(),
        envelope(),
        TimestampNanos::new(100),
        None,
        audit_context(),
    )
}

fn token() -> IdentitySubscriptionToken {
    IdentitySubscriptionToken::new(Subscriber::new(alice()))
}

fn authorization_request_slot() -> AuthorizationRequestSlot {
    AuthorizationRequestSlot::new("authorization-request-1")
}

fn authorization_observation_token() -> AuthorizationObservationToken {
    AuthorizationObservationToken::new(RequestSlot::new(authorization_request_slot()))
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
    AuthorizationGrant::new(
        authorization_request_slot(),
        ObjectDigest::new("digest-lojix-request"),
        contract_name(),
        contract_operation_head(),
        authorization_scope(),
        AuthorizationPolicySatisfaction::new(
            AuthorizationPolicyClass::ComplexQuorum,
            RequiredSignatureThreshold::new(1),
            vec![Identity::Cluster(PrincipalName::new("uranus"))],
        ),
        SignatureAuthorizationResult::RequiredSignaturesSatisfied,
        vec![stamped_envelope()],
        Identity::Cluster(PrincipalName::new("uranus")),
        TimestampNanos::new(110),
        None,
    )
}

fn authorization_state() -> AuthorizationStateRecord {
    AuthorizationStateRecord::new(
        authorization_request_slot(),
        ObjectDigest::new("digest-lojix-request"),
        AuthorizationStatus::Pending,
        vec![Identity::Developer(PrincipalName::new("reviewer"))],
        None,
        None,
    )
}

fn signature_solicitation() -> SignatureSolicitation {
    SignatureSolicitation {
        request_slot: RequestSlot::new(authorization_request_slot()),
        request_digest: RequestDigest::new(ObjectDigest::new("digest-lojix-request")),
        call_contract: CallContract::new(contract_name()),
        call_operation: CallOperation::new(contract_operation_head()),
        call_scope: CallScope::new(authorization_scope()),
        requester: Requester::new(alice()),
        required_signer: RequiredSigner::new(Identity::Developer(PrincipalName::new("reviewer"))),
    }
}

fn contract_digest() -> ContractDigest {
    ContractDigest::new(ObjectDigest::new("contract-digest-1"))
}

fn operation_digest() -> OperationDigest {
    OperationDigest::new(ObjectDigest::new("operation-digest-1"))
}

fn attested_moment() -> AttestedMoment {
    AttestedMoment::new(
        AttestedMomentProposition::new(
            TimeWindow {
                opens_at: OpensAt::new(TimestampNanos::new(10)),
                closes_at: ClosesAt::new(TimestampNanos::new(20)),
            },
            RequiredSignatureThreshold::new(1),
            vec![Identity::Developer(PrincipalName::new("timekeeper"))],
        ),
        vec![TimeSignature {
            signer: Signer::new(Identity::Developer(PrincipalName::new("timekeeper"))),
            envelope: Envelope::new(envelope()),
        }],
    )
}

fn policy_contract() -> Contract {
    Contract::new(Rule::threshold(Threshold::new(
        RequiredSignatureThreshold::new(2),
        vec![
            PolicyMember::key_member(Identity::Developer(PrincipalName::new("operator"))),
            PolicyMember::key_member(Identity::Developer(PrincipalName::new("reviewer"))),
        ],
    )))
}

fn evidence() -> Evidence {
    Evidence::new(
        ComponentKind::Spirit,
        operation_digest(),
        attested_moment(),
        vec![stamped_envelope()],
        Vec::new(),
    )
}

fn authorized_object_update_token() -> AuthorizedObjectUpdateToken {
    AuthorizedObjectUpdateToken {
        subscriber: Subscriber::new(alice()),
        interest: Interest::new(AuthorizedObjectInterest::Component(ComponentKind::Spirit)),
    }
}

fn authorized_object_update() -> AuthorizedObjectUpdate {
    AuthorizedObjectUpdate {
        object: Object::new(AuthorizedObjectReference {
            component: Component::new(ComponentKind::Spirit),
            digest: Digest::new(ObjectDigest::new("operation-digest-1")),
            kind: Kind::new(AuthorizedObjectKind::Operation),
        }),
        contract_object_digest: ContractObjectDigest::new(contract_digest()),
        decision: Decision::new(EvaluationDecision::Authorized),
        stamp: Stamp::new(attested_moment()),
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
    round_trip(CriomeRequest::Sign(SignRequest::new(
        content_reference(),
        alice(),
        audit_context(),
        None,
    )));
    round_trip(CriomeRequest::VerifyAttestation(VerifyRequest {
        attestation: attestation(),
        content: Content::new(content_reference()),
    }));
    round_trip(CriomeRequest::RegisterIdentity(IdentityRegistration::new(
        alice(),
        BlsPublicKey::new("public-key-1"),
        PublicKeyFingerprint::new("fingerprint-1"),
        KeyPurpose::PersonaRequest,
        None,
    )));
    round_trip(CriomeRequest::RevokeIdentity(IdentityRevocation {
        identity: alice(),
        fingerprint: Fingerprint::new(PublicKeyFingerprint::new("fingerprint-1")),
        revocation_reason: RevocationReason::new(PrincipalName::new("revoked-by-owner")),
    }));
    round_trip(CriomeRequest::LookupIdentity(IdentityLookup::new(alice())));
    round_trip(CriomeRequest::AttestArchive(ArchiveAttestationRequest {
        release: Release::new(ComponentRelease {
            release_component: ReleaseComponent::new(PrincipalName::new("persona-router")),
            artifact: Artifact::new(ObjectDigest::new("artifact-1")),
            authorized_by: AuthorizedBy::new(alice()),
        }),
        audit_context: AuditContext {
            purpose: Purpose::new(ContentPurpose::Archive),
            audience: Audience::new(PrincipalName::new("audience-archive")),
            policy_version: PolicyVersion::new(PrincipalName::new("policy-1")),
            nonce: Nonce::new(ReplayNonce::new("nonce-8")),
        },
    }));
    round_trip(CriomeRequest::AttestChannelGrant(
        ChannelGrantAttestationRequest {
            grant_content: GrantContent::new(ContentReference {
                digest: Digest::new(ObjectDigest::new("digest-grant")),
                purpose: Purpose::new(ContentPurpose::ChannelGrant),
                schema_version: SchemaVersion::new(PrincipalName::new("schema-1")),
            }),
            source: Source::new(alice()),
            audit_context: AuditContext {
                purpose: Purpose::new(ContentPurpose::ChannelGrant),
                audience: Audience::new(PrincipalName::new("audience-bob")),
                policy_version: PolicyVersion::new(PrincipalName::new("policy-1")),
                nonce: Nonce::new(ReplayNonce::new("nonce-9")),
            },
        },
    ));
    round_trip(CriomeRequest::AttestAuthorization(
        AuthorizationAttestationRequest {
            authorization_content: AuthorizationContent::new(ContentReference {
                digest: Digest::new(ObjectDigest::new("digest-auth")),
                purpose: Purpose::new(ContentPurpose::Authorization),
                schema_version: SchemaVersion::new(PrincipalName::new("schema-1")),
            }),
            source: Source::new(alice()),
            audit_context: AuditContext {
                purpose: Purpose::new(ContentPurpose::Authorization),
                audience: Audience::new(PrincipalName::new("audience-bob")),
                policy_version: PolicyVersion::new(PrincipalName::new("policy-1")),
                nonce: Nonce::new(ReplayNonce::new("nonce-10")),
            },
        },
    ));
    round_trip(CriomeRequest::AuthorizeSignalCall(
        SignalCallAuthorization::new(
            ObjectDigest::new("digest-lojix-request"),
            contract_name(),
            contract_operation_head(),
            authorization_scope(),
            alice(),
            ReplayNonce::new("authorization-nonce-1"),
            None,
        ),
    ));
    round_trip(CriomeRequest::ObserveAuthorization(
        AuthorizationObservation::new(RequestSlot::new(authorization_request_slot())),
    ));
    round_trip(CriomeRequest::VerifyAuthorization(
        AuthorizationVerification {
            request_digest: RequestDigest::new(ObjectDigest::new("digest-lojix-request")),
            authorization: Authorization::new(authorization_grant()),
        },
    ));
    round_trip(CriomeRequest::RouteSignatureRequest(
        SignatureSolicitationRoute {
            solicitation: Solicitation::new(signature_solicitation()),
            routed_to: RoutedTo::new(Identity::Host(PrincipalName::new("balboa"))),
        },
    ));
    round_trip(CriomeRequest::SubmitSignature(SignatureSubmission {
        request_slot: RequestSlot::new(authorization_request_slot()),
        signer: Signer::new(Identity::Developer(PrincipalName::new("reviewer"))),
        stamped_signature: StampedSignature::new(stamped_envelope()),
    }));
    round_trip(CriomeRequest::RejectAuthorization(AuthorizationRejection {
        request_slot: RequestSlot::new(authorization_request_slot()),
        rejector: Rejector::new(Identity::Developer(PrincipalName::new("reviewer"))),
        denial_reason: DenialReason::new(AuthorizationDenialReason::SignatureRejected),
    }));
    round_trip(CriomeRequest::AdmitContract(policy_contract()));
    round_trip(CriomeRequest::LookupContract(contract_digest()));
    round_trip(CriomeRequest::EvaluateAuthorization(
        AuthorizationEvaluation {
            contract_object_digest: ContractObjectDigest::new(contract_digest()),
            evidence: evidence(),
        },
    ));
    round_trip(CriomeRequest::ObserveAuthorizedObjects(
        AuthorizedObjectObservation {
            subscriber: Subscriber::new(alice()),
            interest: Interest::new(AuthorizedObjectInterest::Component(ComponentKind::Spirit)),
        },
    ));
    round_trip(CriomeRequest::AuthorizedObjectUpdateRetraction(
        authorized_object_update_token(),
    ));
    round_trip(CriomeRequest::SubscribeIdentityUpdates(
        IdentitySubscription::new(Subscriber::new(alice())),
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
        issued_at: IssuedAt::new(TimestampNanos::new(100)),
    }));
    round_trip(CriomeReply::VerificationResult(VerificationResult::new(
        VerificationDecision::Valid,
        Some(alice()),
        None,
    )));
    round_trip(CriomeReply::IdentityReceipt(IdentityReceipt {
        identity: alice(),
        principal_status_role: PrincipalStatusRole::new(PrincipalStatus::Active),
    }));
    round_trip(CriomeReply::IdentitySnapshot(
        IdentitySnapshot::from_identities(vec![IdentityReceipt {
            identity: alice(),
            principal_status_role: PrincipalStatusRole::new(PrincipalStatus::Active),
        }]),
    ));
    round_trip(CriomeReply::AttestationReceipt(AttestationReceipt::new(
        attestation(),
    )));
    round_trip(CriomeReply::AuthorizationPending(
        AuthorizationPending::new(
            authorization_request_slot(),
            ObjectDigest::new("digest-lojix-request"),
            vec![Identity::Developer(PrincipalName::new("reviewer"))],
            authorization_observation_token(),
        ),
    ));
    round_trip(CriomeReply::AuthorizationGranted(authorization_grant()));
    round_trip(CriomeReply::AuthorizationDenied(AuthorizationDenied {
        request_slot: RequestSlot::new(authorization_request_slot()),
        denial_detail: DenialDetail::new(AuthorizationDenial {
            denial_source: DenialSource::new(AuthorizationDenialSource::Policy),
            denial_reason: DenialReason::new(AuthorizationDenialReason::SignatureScopeMismatch),
        }),
    }));
    round_trip(CriomeReply::AuthorizationExpired(AuthorizationExpired {
        request_slot: RequestSlot::new(authorization_request_slot()),
        expired_at: ExpiredAt::new(TimestampNanos::new(111)),
    }));
    round_trip(CriomeReply::AuthorizationUnavailable(
        AuthorizationUnavailable {
            request_slot: RequestSlot::new(authorization_request_slot()),
            unavailable_reason: UnavailableReason::new(PrincipalName::new(
                "criome-peer-unreachable",
            )),
        },
    ));
    round_trip(CriomeReply::AuthorizationObservationSnapshot(
        AuthorizationObservationSnapshot::from_states(vec![authorization_state()]),
    ));
    round_trip(CriomeReply::SignatureRouteReceipt(SignatureRouteReceipt {
        request_slot: RequestSlot::new(authorization_request_slot()),
        routed_to: RoutedTo::new(Identity::Host(PrincipalName::new("balboa"))),
    }));
    round_trip(CriomeReply::SignatureSubmissionReceipt(
        SignatureSubmissionReceipt {
            request_slot: RequestSlot::new(authorization_request_slot()),
            signer: Signer::new(Identity::Developer(PrincipalName::new("reviewer"))),
        },
    ));
    round_trip(CriomeReply::ContractAdmitted(ContractAdmitted::new(
        ContractObjectDigest::new(contract_digest()),
    )));
    round_trip(CriomeReply::ContractFound(ContractFound {
        contract_object_digest: ContractObjectDigest::new(contract_digest()),
        contract: policy_contract(),
    }));
    round_trip(CriomeReply::ContractMissing(ContractMissing::new(
        ContractObjectDigest::new(contract_digest()),
    )));
    round_trip(CriomeReply::ContractAdmissionRejected(
        ContractAdmissionRejected::new(AdmissionRejectionReason::new(
            ContractAdmissionRejectionReason::DuplicatePolicyMember,
        )),
    ));
    round_trip(CriomeReply::AuthorizationEvaluated(
        AuthorizationEvaluated {
            contract_object_digest: ContractObjectDigest::new(contract_digest()),
            decision: Decision::new(EvaluationDecision::Rejected(
                EvaluationRejectionReason::QuorumShort(QuorumShortfall {
                    required: Required::new(RequiredSignatureThreshold::new(2)),
                    satisfied: Satisfied::new(RequiredSignatureThreshold::new(1)),
                }),
            )),
        },
    ));
    round_trip(CriomeReply::AuthorizedObjectUpdateSnapshot(
        AuthorizedObjectUpdateSnapshot::from_updates(vec![authorized_object_update()]),
    ));
    round_trip(CriomeReply::AuthorizedObjectUpdateRetracted(
        AuthorizedObjectUpdateRetracted::new(Token::new(authorized_object_update_token())),
    ));
    round_trip(CriomeReply::AuthorizationObservationRetracted(
        AuthorizationObservationRetracted::new(ObservationToken::new(
            authorization_observation_token(),
        )),
    ));
    round_trip(CriomeReply::SubscriptionRetracted(
        SubscriptionRetracted::new(SubscriptionToken::new(token())),
    ));
    round_trip(CriomeReply::Rejection(Rejection::new(
        RejectionDetail::new(RejectionReason::UnknownIdentity),
    )));
}

#[test]
fn canonical_event_examples_round_trip() {
    round_trip(CriomeEvent::IdentityUpdate(IdentityUpdate::new(
        Receipt::new(IdentityReceipt {
            identity: alice(),
            principal_status_role: PrincipalStatusRole::new(PrincipalStatus::Active),
        }),
    )));
    round_trip(CriomeEvent::AuthorizationUpdate(AuthorizationUpdate::new(
        State::new(authorization_state()),
    )));
    round_trip(CriomeEvent::AuthorizedObjectUpdate(
        authorized_object_update(),
    ));
}
