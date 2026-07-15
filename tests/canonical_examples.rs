//! Canonical examples round-trip witness.
//!
//! Parses `examples/canonical.nota` end-to-end, decoding each record
//! through its NOTA codec and asserting the re-encoded text equals
//! the canonical form. The selection covers the Path A lifecycle
//! and one example per request/reply family. Exhaustive per-variant
//! round-trip witnesses already live in `tests/round_trip.rs`.

use nota::{NotaDecode, NotaEncode, NotaSource};
use signal_criome::{
    ArchiveAttestationRequest, Attestation, AttestationReceipt, AttestedMoment,
    AttestedMomentProposition, AuditContext, AuthorizationAttestationRequest, AuthorizationDenial,
    AuthorizationDenialReason, AuthorizationDenialSource, AuthorizationDenied,
    AuthorizationEvaluated, AuthorizationEvaluation, AuthorizationExpired, AuthorizationGrant,
    AuthorizationObservation, AuthorizationObservationRetracted, AuthorizationObservationSnapshot,
    AuthorizationObservationToken, AuthorizationPending, AuthorizationPolicyClass,
    AuthorizationPolicySatisfaction, AuthorizationRejection, AuthorizationRequestSlot,
    AuthorizationScope, AuthorizationStateRecord, AuthorizationStatus, AuthorizationUnavailable,
    AuthorizationVerification, AuthorizedObjectInterest, AuthorizedObjectKind,
    AuthorizedObjectObservation, AuthorizedObjectReference, AuthorizedObjectUpdate,
    AuthorizedObjectUpdateRetracted, AuthorizedObjectUpdateSnapshot, AuthorizedObjectUpdateToken,
    BlsPublicKey, BlsSignature, ChannelGrantAttestationRequest, ComponentKind, ComponentRelease,
    ContentPurpose, ContentReference, Contract, ContractAdmissionRejected,
    ContractAdmissionRejectionReason, ContractAdmitted, ContractDigest, ContractFound,
    ContractMissing, ContractName, ContractOperationHead, CriomeReply, CriomeRequest,
    EvaluationDecision, EvaluationRejectionReason, Evidence, FoundingConveyance,
    FoundingConveyanceOutcome, FoundingConveyanceReceipt, FoundingMember, FoundingProposal,
    GenesisDomainTag, Identity, IdentityLookup, IdentityReceipt, IdentityRegistration,
    IdentityRevocation, IdentitySnapshot, IdentitySubscription, IdentitySubscriptionToken,
    KeyPurpose, NodePublicKey, NodePublicKeyObservation, ObjectDigest, OperationDigest,
    ParkedAuthorization, ParkedAuthorizationObservation, ParkedAuthorizationSnapshot, PolicyMember,
    PrincipalName, PrincipalStatus, PublicKeyFingerprint, QuorumConflict, QuorumProposal,
    QuorumRoundIdentifier, QuorumRoundQuery, QuorumRoundState, QuorumRoundStatus, QuorumShortfall,
    QuorumVote, QuorumVoteSolicitation, Rejection, RejectionReason, ReplayNonce,
    RequiredSignatureThreshold, RootAnchorDigest, RootGenesis, RoundPhase, Rule, SignReceipt,
    SignRequest, SignalCallAuthorization, SignatureAuthorizationResult, SignatureEnvelope,
    SignatureRouteReceipt, SignatureScheme, SignatureSolicitation, SignatureSolicitationRoute,
    SignatureSubmission, SignatureSubmissionReceipt, StampedSignatureEnvelope,
    SubscriptionRetracted, Threshold, TimeSignature, TimeWindow, TimestampNanos,
    VerificationDecision, VerificationResult, VerifyRequest,
};

const CANONICAL: &str = include_str!("../examples/canonical.nota");

fn alice() -> Identity {
    Identity::Persona(PrincipalName::new("alice"))
}

fn content_reference() -> ContentReference {
    ContentReference {
        object_digest: ObjectDigest::new("digest-abc"),
        content_purpose: ContentPurpose::SignedObject,
        principal_name: PrincipalName::new("schema-1"),
    }
}

fn audit_context() -> AuditContext {
    AuditContext {
        content_purpose: ContentPurpose::SignedObject,
        audience: PrincipalName::new("audience-bob"),
        policy_version: PrincipalName::new("policy-1"),
        replay_nonce: ReplayNonce::new("nonce-7"),
    }
}

fn envelope() -> SignatureEnvelope {
    SignatureEnvelope {
        signature_scheme: SignatureScheme::Bls12_381MinPk,
        bls_public_key: BlsPublicKey::new("public-key-1"),
        bls_signature: BlsSignature::new("signature-1"),
    }
}

fn stamped_envelope() -> StampedSignatureEnvelope {
    StampedSignatureEnvelope {
        attested_moment: attested_moment(),
        signature_envelope: envelope(),
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
    AuthorizationGrant::new(
        authorization_request_slot(),
        AuthorizedObjectReference {
            component_kind: ComponentKind::Lojix,
            object_digest: ObjectDigest::new("digest-lojix-request"),
            authorized_object_kind: AuthorizedObjectKind::Operation,
        },
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
        authorization_request_slot: authorization_request_slot(),
        object_digest: ObjectDigest::new("digest-lojix-request"),
        contract_name: contract_name(),
        contract_operation_head: contract_operation_head(),
        authorization_scope: authorization_scope(),
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
    AttestedMoment::new(
        AttestedMomentProposition::new(
            TimeWindow {
                opens_at: TimestampNanos::new(10),
                closes_at: TimestampNanos::new(20),
            },
            RequiredSignatureThreshold::new(1),
            vec![Identity::Developer(PrincipalName::new("timekeeper"))],
        ),
        vec![TimeSignature {
            identity: Identity::Developer(PrincipalName::new("timekeeper")),
            signature_envelope: envelope(),
        }],
    )
}

fn policy_contract() -> Contract {
    Contract::root(Rule::threshold_rule(Threshold::new(
        RequiredSignatureThreshold::new(2),
        vec![
            PolicyMember::key_member(Identity::Developer(PrincipalName::new("operator"))),
            PolicyMember::key_member(Identity::Developer(PrincipalName::new("reviewer"))),
        ],
    )))
}

fn node_public_key() -> NodePublicKey {
    NodePublicKey::new(BlsPublicKey::new("node-master-pubkey"))
}

fn founding_member(name: &str) -> FoundingMember {
    FoundingMember::new(
        Identity::Host(PrincipalName::new(name)),
        BlsPublicKey::new(format!("{name}-master-pubkey")),
    )
}

fn root_genesis() -> RootGenesis {
    RootGenesis::new(
        Contract::root(Rule::threshold_rule(Threshold::new(
            RequiredSignatureThreshold::new(2),
            vec![
                PolicyMember::key_member(Identity::Host(PrincipalName::new("mirror-alpha"))),
                PolicyMember::key_member(Identity::Host(PrincipalName::new("mirror-beta"))),
            ],
        ))),
        vec![
            founding_member("mirror-alpha"),
            founding_member("mirror-beta"),
        ],
        GenesisDomainTag::CriomeRootFoundingV1,
        ReplayNonce::new("genesis-nonce-1"),
    )
}

fn root_anchor() -> RootAnchorDigest {
    RootAnchorDigest::new(ObjectDigest::new("root-anchor-1"))
}

fn founding_conveyance_proposal() -> FoundingConveyance {
    FoundingConveyance::Proposal(FoundingProposal {
        root_genesis: root_genesis(),
        identity: Identity::Host(PrincipalName::new("mirror-alpha")),
    })
}

fn founding_conveyance_receipt() -> FoundingConveyanceReceipt {
    FoundingConveyanceReceipt {
        root_anchor_digest: root_anchor(),
        founding_conveyance_outcome: FoundingConveyanceOutcome::RootFounded,
    }
}

fn quorum_conflict() -> QuorumConflict {
    QuorumConflict::new(
        contract_digest(),
        ContractOperationHead::new("head-1"),
        authorized_object_reference(),
    )
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
        identity: alice(),
        authorized_object_interest: AuthorizedObjectInterest::Component(ComponentKind::Spirit),
    }
}

fn authorized_object_reference() -> AuthorizedObjectReference {
    AuthorizedObjectReference {
        component_kind: ComponentKind::Spirit,
        object_digest: operation_digest().object_digest().clone(),
        authorized_object_kind: AuthorizedObjectKind::Head,
    }
}

fn authorized_object_update() -> AuthorizedObjectUpdate {
    AuthorizedObjectUpdate {
        authorized_object_reference: authorized_object_reference(),
        contract_digest: contract_digest(),
        evaluation_decision: EvaluationDecision::Authorized,
        attested_moment: attested_moment(),
    }
}

fn authorization_evaluation() -> AuthorizationEvaluation {
    AuthorizationEvaluation {
        contract_digest: contract_digest(),
        authorized_object_reference: authorized_object_reference(),
        evidence: evidence(),
    }
}

fn quorum_round_identifier() -> QuorumRoundIdentifier {
    QuorumRoundIdentifier::new("quorum-round-1")
}

fn quorum_moment_proposition() -> AttestedMomentProposition {
    AttestedMomentProposition::new(
        TimeWindow {
            opens_at: TimestampNanos::new(10),
            closes_at: TimestampNanos::new(20),
        },
        RequiredSignatureThreshold::new(2),
        vec![
            Identity::Host(PrincipalName::new("mirror-alpha")),
            Identity::Host(PrincipalName::new("mirror-beta")),
        ],
    )
}

fn quorum_proposal() -> QuorumProposal {
    QuorumProposal {
        quorum_round_identifier: quorum_round_identifier(),
        round_phase: RoundPhase::Request,
        contract_digest: contract_digest(),
        authorized_object_reference: authorized_object_reference(),
        time_window: TimeWindow {
            opens_at: TimestampNanos::new(10),
            closes_at: TimestampNanos::new(20),
        },
    }
}

fn quorum_vote_solicitation() -> QuorumVoteSolicitation {
    QuorumVoteSolicitation {
        quorum_round_identifier: quorum_round_identifier(),
        round_phase: RoundPhase::Request,
        contract_digest: contract_digest(),
        authorized_object_reference: authorized_object_reference(),
        attested_moment_proposition: quorum_moment_proposition(),
        identity: Identity::Host(PrincipalName::new("mirror-alpha")),
    }
}

fn quorum_vote() -> QuorumVote {
    QuorumVote {
        quorum_round_identifier: quorum_round_identifier(),
        round_phase: RoundPhase::Request,
        identity: Identity::Host(PrincipalName::new("mirror-beta")),
        operation_signature: envelope(),
        time_signature: envelope(),
    }
}

fn quorum_round_state() -> QuorumRoundState {
    QuorumRoundState {
        quorum_round_identifier: quorum_round_identifier(),
        round_phase: RoundPhase::Request,
        contract_digest: contract_digest(),
        quorum_round_status: QuorumRoundStatus::Authorized,
        gathered: RequiredSignatureThreshold::new(2),
        required: RequiredSignatureThreshold::new(2),
        optional_evidence: Some(evidence()),
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
        content_reference: content_reference(),
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
        public_key_fingerprint: PublicKeyFingerprint::new("fingerprint-1"),
        principal_name: PrincipalName::new("revoked-by-owner"),
    }));
    round_trip(CriomeRequest::LookupIdentity(IdentityLookup::new(alice())));
    round_trip(CriomeRequest::AttestArchive(ArchiveAttestationRequest {
        component_release: ComponentRelease {
            principal_name: PrincipalName::new("persona-router"),
            object_digest: ObjectDigest::new("artifact-1"),
            identity: alice(),
        },
        audit_context: AuditContext {
            content_purpose: ContentPurpose::Archive,
            audience: PrincipalName::new("audience-archive"),
            policy_version: PrincipalName::new("policy-1"),
            replay_nonce: ReplayNonce::new("nonce-8"),
        },
    }));
    round_trip(CriomeRequest::AttestChannelGrant(
        ChannelGrantAttestationRequest {
            content_reference: ContentReference {
                object_digest: ObjectDigest::new("digest-grant"),
                content_purpose: ContentPurpose::ChannelGrant,
                principal_name: PrincipalName::new("schema-1"),
            },
            identity: alice(),
            audit_context: AuditContext {
                content_purpose: ContentPurpose::ChannelGrant,
                audience: PrincipalName::new("audience-bob"),
                policy_version: PrincipalName::new("policy-1"),
                replay_nonce: ReplayNonce::new("nonce-9"),
            },
        },
    ));
    round_trip(CriomeRequest::AttestAuthorization(
        AuthorizationAttestationRequest {
            content_reference: ContentReference {
                object_digest: ObjectDigest::new("digest-auth"),
                content_purpose: ContentPurpose::Authorization,
                principal_name: PrincipalName::new("schema-1"),
            },
            identity: alice(),
            audit_context: AuditContext {
                content_purpose: ContentPurpose::Authorization,
                audience: PrincipalName::new("audience-bob"),
                policy_version: PrincipalName::new("policy-1"),
                replay_nonce: ReplayNonce::new("nonce-10"),
            },
        },
    ));
    round_trip(CriomeRequest::AuthorizeSignalCall(
        SignalCallAuthorization::new(
            AuthorizedObjectReference {
                component_kind: ComponentKind::Lojix,
                object_digest: ObjectDigest::new("digest-lojix-request"),
                authorized_object_kind: AuthorizedObjectKind::Operation,
            },
            alice(),
            ReplayNonce::new("authorization-nonce-1"),
            None,
        ),
    ));
    round_trip(CriomeRequest::ObserveAuthorization(
        AuthorizationObservation::new(authorization_request_slot()),
    ));
    round_trip(CriomeRequest::ObserveParkedAuthorizations(
        ParkedAuthorizationObservation::new(),
    ));
    round_trip(CriomeRequest::VerifyAuthorization(
        AuthorizationVerification {
            object_digest: ObjectDigest::new("digest-lojix-request"),
            authorization_grant: authorization_grant(),
        },
    ));
    round_trip(CriomeRequest::RouteSignatureRequest(
        SignatureSolicitationRoute {
            signature_solicitation: signature_solicitation(),
            identity: Identity::Host(PrincipalName::new("balboa")),
        },
    ));
    round_trip(CriomeRequest::SubmitSignature(SignatureSubmission {
        authorization_request_slot: authorization_request_slot(),
        identity: Identity::Developer(PrincipalName::new("reviewer")),
        stamped_signature_envelope: stamped_envelope(),
    }));
    round_trip(CriomeRequest::RejectAuthorization(AuthorizationRejection {
        authorization_request_slot: authorization_request_slot(),
        identity: Identity::Developer(PrincipalName::new("reviewer")),
        authorization_denial_reason: AuthorizationDenialReason::SignatureRejected,
    }));
    round_trip(CriomeRequest::AdmitContract(policy_contract()));
    round_trip(CriomeRequest::LookupContract(contract_digest()));
    round_trip(CriomeRequest::EvaluateAuthorization(
        authorization_evaluation(),
    ));
    round_trip(CriomeRequest::ObserveAuthorizedObjects(
        AuthorizedObjectObservation {
            identity: alice(),
            authorized_object_interest: AuthorizedObjectInterest::Component(ComponentKind::Spirit),
        },
    ));
    round_trip(CriomeRequest::AuthorizedObjectUpdateRetraction(
        authorized_object_update_token(),
    ));
    round_trip(CriomeRequest::SubscribeIdentityUpdates(
        IdentitySubscription::new(alice()),
    ));
    round_trip(CriomeRequest::IdentitySubscriptionRetraction(token()));
    round_trip(CriomeRequest::AuthorizationObservationRetraction(
        authorization_observation_token(),
    ));
    round_trip(CriomeRequest::ProposeQuorumAuthorization(quorum_proposal()));
    round_trip(CriomeRequest::SolicitQuorumVote(quorum_vote_solicitation()));
    round_trip(CriomeRequest::SubmitQuorumVote(quorum_vote()));
    round_trip(CriomeRequest::ObserveQuorumRound(QuorumRoundQuery::new(
        quorum_round_identifier(),
    )));
    round_trip(CriomeRequest::ObserveNodePublicKey(
        NodePublicKeyObservation::new(),
    ));
    round_trip(CriomeRequest::ConveyFounding(founding_conveyance_proposal()));
}

#[test]
fn canonical_reply_examples_round_trip() {
    round_trip(CriomeReply::Signed(SignReceipt {
        attestation: attestation(),
        timestamp_nanos: TimestampNanos::new(100),
    }));
    round_trip(CriomeReply::Verified(VerificationResult::new(
        VerificationDecision::Valid,
        Some(alice()),
        None,
    )));
    round_trip(CriomeReply::IdentityRegistered(IdentityReceipt {
        identity: alice(),
        principal_status: PrincipalStatus::Active,
    }));
    round_trip(CriomeReply::Identities(IdentitySnapshot::from_identities(
        vec![IdentityReceipt {
            identity: alice(),
            principal_status: PrincipalStatus::Active,
        }],
    )));
    round_trip(CriomeReply::Attested(
        AttestationReceipt::new(attestation()),
    ));
    round_trip(CriomeReply::Pending(AuthorizationPending::new(
        authorization_request_slot(),
        ObjectDigest::new("digest-lojix-request"),
        vec![Identity::Developer(PrincipalName::new("reviewer"))],
        authorization_observation_token(),
    )));
    round_trip(CriomeReply::AuthorizationGranted(authorization_grant()));
    round_trip(CriomeReply::Denied(AuthorizationDenied {
        authorization_request_slot: authorization_request_slot(),
        authorization_denial: AuthorizationDenial {
            authorization_denial_source: AuthorizationDenialSource::Policy,
            authorization_denial_reason: AuthorizationDenialReason::SignatureScopeMismatch,
        },
    }));
    round_trip(CriomeReply::Expired(AuthorizationExpired {
        authorization_request_slot: authorization_request_slot(),
        timestamp_nanos: TimestampNanos::new(111),
    }));
    round_trip(CriomeReply::Unavailable(AuthorizationUnavailable {
        authorization_request_slot: authorization_request_slot(),
        principal_name: PrincipalName::new("criome-peer-unreachable"),
    }));
    round_trip(CriomeReply::AuthorizationObserved(
        AuthorizationObservationSnapshot::from_states(vec![authorization_state()]),
    ));
    round_trip(CriomeReply::ParkedAuthorizations(
        ParkedAuthorizationSnapshot::from_parked(vec![ParkedAuthorization::from_evaluation(
            authorization_request_slot(),
            authorization_evaluation(),
        )]),
    ));
    round_trip(CriomeReply::SignatureRouted(SignatureRouteReceipt {
        authorization_request_slot: authorization_request_slot(),
        identity: Identity::Host(PrincipalName::new("balboa")),
    }));
    round_trip(CriomeReply::SignatureSubmitted(
        SignatureSubmissionReceipt {
            authorization_request_slot: authorization_request_slot(),
            identity: Identity::Developer(PrincipalName::new("reviewer")),
        },
    ));
    round_trip(CriomeReply::ContractAccepted(ContractAdmitted::new(
        contract_digest(),
    )));
    round_trip(CriomeReply::ContractLocated(ContractFound {
        contract_digest: contract_digest(),
        contract: policy_contract(),
    }));
    round_trip(CriomeReply::ContractAbsent(ContractMissing::new(
        contract_digest(),
    )));
    round_trip(CriomeReply::ContractRefused(
        ContractAdmissionRejected::new(ContractAdmissionRejectionReason::DuplicatePolicyMember),
    ));
    round_trip(CriomeReply::AuthorizationJudged(AuthorizationEvaluated {
        contract_digest: contract_digest(),
        evaluation_decision: EvaluationDecision::Rejected(EvaluationRejectionReason::QuorumShort(
            QuorumShortfall {
                required: RequiredSignatureThreshold::new(2),
                satisfied: RequiredSignatureThreshold::new(1),
            },
        )),
    }));
    round_trip(CriomeReply::AuthorizedObjectsUpdated(
        AuthorizedObjectUpdateSnapshot::from_updates(vec![authorized_object_update()]),
    ));
    round_trip(CriomeReply::AuthorizedObjectRetracted(
        AuthorizedObjectUpdateRetracted::new(authorized_object_update_token()),
    ));
    round_trip(CriomeReply::AuthorizationObservationClosed(
        AuthorizationObservationRetracted::new(authorization_observation_token()),
    ));
    round_trip(CriomeReply::SubscriptionClosed(SubscriptionRetracted::new(
        token(),
    )));
    round_trip(CriomeReply::Refused(Rejection::new(
        RejectionReason::UnknownIdentity,
    )));
    round_trip(CriomeReply::QuorumRoundOpened(quorum_round_state()));
    round_trip(CriomeReply::QuorumVoteSolicited(quorum_round_state()));
    round_trip(CriomeReply::QuorumVoteAccepted(quorum_round_state()));
    round_trip(CriomeReply::QuorumRoundObserved(quorum_round_state()));
    round_trip(CriomeReply::PublicKeyObserved(node_public_key()));
    round_trip(CriomeReply::QuorumRefused(quorum_conflict()));
    round_trip(CriomeReply::FoundingConveyed(founding_conveyance_receipt()));
}
