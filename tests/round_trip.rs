use nota_next::{NotaDecode, NotaEncode, NotaSource};
use signal_criome::{
    AdmissionRejectionReason, Artifact, Audience, Authorization, AuthorizationContent,
    AuthorizedBy, CallContract, CallOperation, CallScope, ClosesAt, Component, Content,
    ContractObjectDigest, Decision, DenialDetail, DenialReason, DenialSource, Digest, Envelope,
    EnvelopeSignature, ExpiredAt, Fingerprint, GrantContent, Interest, IssuedAt, Kind, Nonce,
    Object, ObservationToken, OpensAt, PolicyVersion, PrincipalStatusRole, PublicKey, Purpose,
    Receipt, RejectionDetail, Rejector, Release, ReleaseComponent, RequestDigest, RequestSlot,
    Requester, Required, RequiredSigner, RevocationReason, RoutedTo, Satisfied, SchemaVersion,
    Scheme, Signer, Solicitation, Source, Stamp, StampedSignature, State, Subscriber,
    SubscriptionToken, Token, UnavailableReason,
};
use signal_criome::{
    ArchiveAttestationRequest, Attestation, AttestationReceipt, AttestedMoment,
    AttestedMomentProposition, AuditContext, AuthorizationDenial, AuthorizationDenialReason,
    AuthorizationDenialSource, AuthorizationDenied, AuthorizationEvaluated,
    AuthorizationEvaluation, AuthorizationExpired, AuthorizationGrant, AuthorizationObservation,
    AuthorizationObservationRetracted, AuthorizationObservationSnapshot,
    AuthorizationObservationToken, AuthorizationPending, AuthorizationPolicyClass,
    AuthorizationPolicySatisfaction, AuthorizationRejection, AuthorizationRequestSlot,
    AuthorizationScope, AuthorizationStateRecord, AuthorizationStatus, AuthorizationUnavailable,
    AuthorizationUpdate, AuthorizationVerification, AuthorizedObjectInterest, AuthorizedObjectKind,
    AuthorizedObjectObservation, AuthorizedObjectReference, AuthorizedObjectUpdate,
    AuthorizedObjectUpdateRetracted, AuthorizedObjectUpdateSnapshot, AuthorizedObjectUpdateToken,
    BlsPublicKey, BlsSignature, ChannelGrantAttestationRequest, ComponentKind, ComponentRelease,
    ContentPurpose, ContentReference, Contract, ContractAdmissionRejected,
    ContractAdmissionRejectionReason, ContractAdmitted, ContractDigest, ContractFound,
    ContractMissing, ContractName, ContractOperationHead, CriomeEvent, CriomeFrame as Frame,
    CriomeFrameBody as FrameBody, CriomeReply, CriomeRequest, EvaluationDecision,
    EvaluationRejectionReason, Evidence, Identity, IdentityLookup, IdentityReceipt,
    IdentityRegistration, IdentityRevocation, IdentitySnapshot, IdentitySubscription,
    IdentitySubscriptionToken, IdentityUpdate, KeyPurpose, ObjectDigest, OperationDigest,
    PolicyMember, PrincipalName, PrincipalStatus, PublicKeyFingerprint, QuorumShortfall, Rejection,
    RejectionReason, ReplayNonce, RequiredSignatureThreshold, Rule, SignReceipt, SignRequest,
    SignalCallAuthorization, SignatureAuthorizationResult, SignatureEnvelope,
    SignatureRouteReceipt, SignatureScheme, SignatureSolicitation, SignatureSolicitationRoute,
    SignatureSubmission, SignatureSubmissionReceipt, StampedSignatureEnvelope,
    SubscriptionRetracted, Threshold, TimeSignature, TimeWindow, TimestampNanos,
    VerificationDecision, VerificationResult, VerifyRequest,
};
use signal_frame::{
    ExchangeIdentifier, ExchangeLane, LaneSequence, NonEmpty, Reply, RequestPayload, SessionEpoch,
    SignalOperationHeads, StreamEventIdentifier, SubReply, SubscriptionTokenInner,
};

fn persona(name: &str) -> Identity {
    Identity::persona(name.to_owned())
}

fn agent(name: &str) -> Identity {
    Identity::agent(name.to_owned())
}

fn host(name: &str) -> Identity {
    Identity::host(name.to_owned())
}

fn developer(name: &str) -> Identity {
    Identity::developer(name.to_owned())
}

fn cluster(name: &str) -> Identity {
    Identity::cluster(name.to_owned())
}

fn content(purpose: ContentPurpose) -> ContentReference {
    ContentReference {
        digest: Digest::new(ObjectDigest::from_bytes(b"contract fixture")),
        purpose: Purpose::new(purpose),
        schema_version: SchemaVersion::new(PrincipalName::new("signal-criome/0")),
    }
}

fn audit(purpose: ContentPurpose) -> AuditContext {
    AuditContext {
        purpose: Purpose::new(purpose),
        audience: Audience::new(PrincipalName::new("persona-engine")),
        policy_version: PolicyVersion::new(PrincipalName::new("policy-v1")),
        nonce: Nonce::new(ReplayNonce::new("nonce-1")),
    }
}

fn envelope() -> SignatureEnvelope {
    SignatureEnvelope {
        scheme: Scheme::new(SignatureScheme::Bls12_381MinPk),
        public_key: PublicKey::new(BlsPublicKey::new("bls-pubkey-fixture")),
        envelope_signature: EnvelopeSignature::new(BlsSignature::new("bls-signature-fixture")),
    }
}

fn stamped_envelope() -> StampedSignatureEnvelope {
    StampedSignatureEnvelope {
        stamp: Stamp::new(attested_moment()),
        envelope: Envelope::new(envelope()),
    }
}

fn attestation(purpose: ContentPurpose) -> Attestation {
    Attestation::new(
        content(purpose),
        developer("operator"),
        envelope(),
        TimestampNanos::new(1),
        Some(TimestampNanos::new(2)),
        audit(purpose),
    )
}

fn authorization_request_slot() -> AuthorizationRequestSlot {
    AuthorizationRequestSlot::new("authorization-request-1")
}

fn authorization_scope() -> AuthorizationScope {
    AuthorizationScope::new("deploy:zeus:FullOs")
}

fn contract_name() -> ContractName {
    ContractName::new("signal-lojix")
}

fn contract_operation_head() -> ContractOperationHead {
    ContractOperationHead::new("Deploy")
}

fn signal_call_authorization() -> SignalCallAuthorization {
    SignalCallAuthorization::new(
        ObjectDigest::from_bytes(b"signal-lojix request"),
        contract_name(),
        contract_operation_head(),
        authorization_scope(),
        developer("operator"),
        ReplayNonce::new("authorization-nonce-1"),
        Some(TimestampNanos::new(10)),
    )
}

fn authorization_observation_token() -> AuthorizationObservationToken {
    AuthorizationObservationToken::new(RequestSlot::new(authorization_request_slot()))
}

fn authorization_grant() -> AuthorizationGrant {
    AuthorizationGrant::new(
        authorization_request_slot(),
        ObjectDigest::from_bytes(b"signal-lojix request"),
        contract_name(),
        contract_operation_head(),
        authorization_scope(),
        AuthorizationPolicySatisfaction::new(
            AuthorizationPolicyClass::ComplexQuorum,
            RequiredSignatureThreshold::new(1),
            vec![cluster("uranus")],
        ),
        SignatureAuthorizationResult::RequiredSignaturesSatisfied,
        vec![stamped_envelope()],
        cluster("uranus"),
        TimestampNanos::new(11),
        Some(TimestampNanos::new(12)),
    )
}

fn authorization_state(status: AuthorizationStatus) -> AuthorizationStateRecord {
    AuthorizationStateRecord::new(
        authorization_request_slot(),
        ObjectDigest::from_bytes(b"signal-lojix request"),
        status,
        vec![developer("reviewer")],
        (status == AuthorizationStatus::Granted).then(authorization_grant),
        (status == AuthorizationStatus::Denied).then_some(AuthorizationDenial {
            denial_source: DenialSource::new(AuthorizationDenialSource::Signers),
            denial_reason: DenialReason::new(AuthorizationDenialReason::SignatureRejected),
        }),
    )
}

fn signature_solicitation() -> SignatureSolicitation {
    SignatureSolicitation {
        request_slot: RequestSlot::new(authorization_request_slot()),
        request_digest: RequestDigest::new(ObjectDigest::from_bytes(b"signal-lojix request")),
        call_contract: CallContract::new(contract_name()),
        call_operation: CallOperation::new(contract_operation_head()),
        call_scope: CallScope::new(authorization_scope()),
        requester: Requester::new(developer("operator")),
        required_signer: RequiredSigner::new(developer("reviewer")),
    }
}

fn contract_digest() -> ContractDigest {
    ContractDigest::from_bytes(b"contract fixture")
}

fn operation_digest() -> OperationDigest {
    OperationDigest::from_bytes(b"operation fixture")
}

fn attested_moment() -> AttestedMoment {
    AttestedMoment::new(
        AttestedMomentProposition::new(
            TimeWindow {
                opens_at: OpensAt::new(TimestampNanos::new(10)),
                closes_at: ClosesAt::new(TimestampNanos::new(20)),
            },
            RequiredSignatureThreshold::new(1),
            vec![developer("timekeeper")],
        ),
        vec![TimeSignature {
            signer: Signer::new(developer("timekeeper")),
            envelope: Envelope::new(envelope()),
        }],
    )
}

fn policy_contract() -> Contract {
    Contract::new(Rule::threshold(Threshold::new(
        RequiredSignatureThreshold::new(2),
        vec![
            PolicyMember::key_member(developer("operator")),
            PolicyMember::key_member(developer("reviewer")),
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
        subscriber: Subscriber::new(agent("operator")),
        interest: Interest::new(AuthorizedObjectInterest::Component(ComponentKind::Spirit)),
    }
}

fn authorized_object_update() -> AuthorizedObjectUpdate {
    AuthorizedObjectUpdate {
        object: Object::new(AuthorizedObjectReference {
            component: Component::new(ComponentKind::Spirit),
            digest: Digest::new(ObjectDigest::from_bytes(b"operation fixture")),
            kind: Kind::new(AuthorizedObjectKind::Operation),
        }),
        contract_object_digest: ContractObjectDigest::new(contract_digest()),
        decision: Decision::new(EvaluationDecision::Authorized),
        stamp: Stamp::new(attested_moment()),
    }
}

fn exchange() -> ExchangeIdentifier {
    ExchangeIdentifier::new(
        SessionEpoch::new(1),
        ExchangeLane::Connector,
        LaneSequence::first(),
    )
}

fn stream_event() -> StreamEventIdentifier {
    StreamEventIdentifier::new(
        SessionEpoch::new(1),
        ExchangeLane::Acceptor,
        LaneSequence::first(),
    )
}

fn round_trip_request(request: CriomeRequest) -> CriomeRequest {
    let frame = Frame::new(FrameBody::Request {
        exchange: exchange(),
        request: request.into_request(),
    });
    let bytes = frame.encode_length_prefixed().expect("encode request");
    let decoded = Frame::decode_length_prefixed(&bytes).expect("decode request");

    match decoded.into_body() {
        FrameBody::Request { request, .. } => request.payloads().head().clone(),
        other => panic!("expected request operation, got {other:?}"),
    }
}

fn round_trip_reply(reply: CriomeReply) -> CriomeReply {
    let frame = Frame::new(FrameBody::Reply {
        exchange: exchange(),
        reply: Reply::committed(NonEmpty::single(SubReply::Ok(reply))),
    });
    let bytes = frame.encode_length_prefixed().expect("encode reply");
    let decoded = Frame::decode_length_prefixed(&bytes).expect("decode reply");

    match decoded.into_body() {
        FrameBody::Reply { reply, .. } => match reply {
            Reply::Accepted { per_operation, .. } => match per_operation.into_head() {
                SubReply::Ok(payload) => payload,
                other => panic!("expected accepted reply payload, got {other:?}"),
            },
            other => panic!("expected accepted reply, got {other:?}"),
        },
        other => panic!("expected reply operation, got {other:?}"),
    }
}

fn round_trip_event(event: CriomeEvent) -> CriomeEvent {
    let frame = Frame::new(FrameBody::SubscriptionEvent {
        event_identifier: stream_event(),
        token: SubscriptionTokenInner::new(1),
        event,
    });
    let bytes = frame.encode_length_prefixed().expect("encode event");
    let decoded = Frame::decode_length_prefixed(&bytes).expect("decode event");

    match decoded.into_body() {
        FrameBody::SubscriptionEvent { event, .. } => event,
        other => panic!("expected subscription event, got {other:?}"),
    }
}

fn round_trip_nota<T>(value: T, expected: &str)
where
    T: NotaEncode + NotaDecode + PartialEq + std::fmt::Debug,
{
    let encoded = value.to_nota();
    assert_eq!(encoded, expected);

    let recovered = NotaSource::new(&encoded).parse::<T>().expect("decode nota");
    assert_eq!(recovered, value);
}

#[test]
fn request_variants_round_trip_through_length_prefixed_frame() {
    let requests = vec![
        CriomeRequest::Sign(SignRequest::new(
            content(ContentPurpose::SignedObject),
            developer("operator"),
            audit(ContentPurpose::SignedObject),
            None,
        )),
        CriomeRequest::VerifyAttestation(VerifyRequest {
            attestation: attestation(ContentPurpose::SignedObject),
            content: Content::new(content(ContentPurpose::SignedObject)),
        }),
        CriomeRequest::RegisterIdentity(IdentityRegistration::new(
            persona("designer"),
            BlsPublicKey::new("designer-public-key"),
            PublicKeyFingerprint::new("fingerprint-designer"),
            KeyPurpose::PersonaRequest,
            None,
        )),
        CriomeRequest::RevokeIdentity(IdentityRevocation {
            identity: persona("designer"),
            fingerprint: Fingerprint::new(PublicKeyFingerprint::new("fingerprint-designer")),
            revocation_reason: RevocationReason::new(PrincipalName::new("retired")),
        }),
        CriomeRequest::LookupIdentity(IdentityLookup::new(host("prometheus"))),
        CriomeRequest::AttestArchive(ArchiveAttestationRequest {
            release: Release::new(ComponentRelease {
                release_component: ReleaseComponent::new(PrincipalName::new("persona-router")),
                artifact: Artifact::new(ObjectDigest::from_bytes(b"closure")),
                authorized_by: AuthorizedBy::new(developer("operator")),
            }),
            audit_context: audit(ContentPurpose::Archive),
        }),
        CriomeRequest::AttestChannelGrant(ChannelGrantAttestationRequest {
            grant_content: GrantContent::new(content(ContentPurpose::ChannelGrant)),
            source: Source::new(persona("mind")),
            audit_context: audit(ContentPurpose::ChannelGrant),
        }),
        CriomeRequest::AttestAuthorization(signal_criome::AuthorizationAttestationRequest {
            authorization_content: AuthorizationContent::new(content(
                ContentPurpose::Authorization,
            )),
            source: Source::new(persona("mind")),
            audit_context: audit(ContentPurpose::Authorization),
        }),
        CriomeRequest::AuthorizeSignalCall(signal_call_authorization()),
        CriomeRequest::ObserveAuthorization(AuthorizationObservation::new(RequestSlot::new(
            authorization_request_slot(),
        ))),
        CriomeRequest::VerifyAuthorization(AuthorizationVerification {
            request_digest: RequestDigest::new(ObjectDigest::from_bytes(b"signal-lojix request")),
            authorization: Authorization::new(authorization_grant()),
        }),
        CriomeRequest::RouteSignatureRequest(SignatureSolicitationRoute {
            solicitation: Solicitation::new(signature_solicitation()),
            routed_to: RoutedTo::new(host("balboa")),
        }),
        CriomeRequest::SubmitSignature(SignatureSubmission {
            request_slot: RequestSlot::new(authorization_request_slot()),
            signer: Signer::new(developer("reviewer")),
            stamped_signature: StampedSignature::new(stamped_envelope()),
        }),
        CriomeRequest::RejectAuthorization(AuthorizationRejection {
            request_slot: RequestSlot::new(authorization_request_slot()),
            rejector: Rejector::new(developer("reviewer")),
            denial_reason: DenialReason::new(AuthorizationDenialReason::SignatureRejected),
        }),
        CriomeRequest::AdmitContract(policy_contract()),
        CriomeRequest::LookupContract(contract_digest()),
        CriomeRequest::EvaluateAuthorization(AuthorizationEvaluation {
            contract_object_digest: ContractObjectDigest::new(contract_digest()),
            evidence: evidence(),
        }),
        CriomeRequest::ObserveAuthorizedObjects(AuthorizedObjectObservation {
            subscriber: Subscriber::new(agent("operator")),
            interest: Interest::new(AuthorizedObjectInterest::Component(ComponentKind::Spirit)),
        }),
        CriomeRequest::AuthorizedObjectUpdateRetraction(authorized_object_update_token()),
        CriomeRequest::SubscribeIdentityUpdates(IdentitySubscription::new(Subscriber::new(agent(
            "operator",
        )))),
        CriomeRequest::IdentitySubscriptionRetraction(IdentitySubscriptionToken::new(
            Subscriber::new(agent("operator")),
        )),
        CriomeRequest::AuthorizationObservationRetraction(authorization_observation_token()),
    ];

    for request in requests {
        assert_eq!(round_trip_request(request.clone()), request);
    }
}

#[test]
fn request_variants_declare_contract_local_operation_heads() {
    assert_eq!(
        <CriomeRequest as SignalOperationHeads>::HEADS,
        &[
            "Sign",
            "VerifyAttestation",
            "RegisterIdentity",
            "RevokeIdentity",
            "LookupIdentity",
            "AttestArchive",
            "AttestChannelGrant",
            "AttestAuthorization",
            "AuthorizeSignalCall",
            "ObserveAuthorization",
            "VerifyAuthorization",
            "RouteSignatureRequest",
            "SubmitSignature",
            "RejectAuthorization",
            "AdmitContract",
            "LookupContract",
            "EvaluateAuthorization",
            "ObserveAuthorizedObjects",
            "AuthorizedObjectUpdateRetraction",
            "ScheduleContractTimeCheck",
            "RunDueContractChecks",
            "SubscribeIdentityUpdates",
            "IdentitySubscriptionRetraction",
            "AuthorizationObservationRetraction",
        ]
    );
}

#[test]
fn reply_variants_round_trip_through_length_prefixed_frame() {
    let receipt = IdentityReceipt {
        identity: persona("designer"),
        principal_status_role: PrincipalStatusRole::new(PrincipalStatus::Active),
    };
    let replies = vec![
        CriomeReply::SignReceipt(SignReceipt {
            attestation: attestation(ContentPurpose::SignedObject),
            issued_at: IssuedAt::new(TimestampNanos::new(1)),
        }),
        CriomeReply::VerificationResult(VerificationResult::new(
            VerificationDecision::Valid,
            Some(developer("operator")),
            Some(TimestampNanos::new(2)),
        )),
        CriomeReply::IdentityReceipt(receipt.clone()),
        CriomeReply::IdentitySnapshot(IdentitySnapshot::from_identities(vec![receipt.clone()])),
        CriomeReply::AttestationReceipt(AttestationReceipt::new(attestation(
            ContentPurpose::Archive,
        ))),
        CriomeReply::AuthorizationPending(AuthorizationPending::new(
            authorization_request_slot(),
            ObjectDigest::from_bytes(b"signal-lojix request"),
            vec![developer("reviewer")],
            authorization_observation_token(),
        )),
        CriomeReply::AuthorizationGranted(authorization_grant()),
        CriomeReply::AuthorizationDenied(AuthorizationDenied {
            request_slot: RequestSlot::new(authorization_request_slot()),
            denial_detail: DenialDetail::new(AuthorizationDenial {
                denial_source: DenialSource::new(AuthorizationDenialSource::Policy),
                denial_reason: DenialReason::new(AuthorizationDenialReason::SignatureScopeMismatch),
            }),
        }),
        CriomeReply::AuthorizationExpired(AuthorizationExpired {
            request_slot: RequestSlot::new(authorization_request_slot()),
            expired_at: ExpiredAt::new(TimestampNanos::new(13)),
        }),
        CriomeReply::AuthorizationUnavailable(AuthorizationUnavailable {
            request_slot: RequestSlot::new(authorization_request_slot()),
            unavailable_reason: UnavailableReason::new(PrincipalName::new(
                "criome-peer-unreachable",
            )),
        }),
        CriomeReply::AuthorizationObservationSnapshot(
            AuthorizationObservationSnapshot::from_states(vec![authorization_state(
                AuthorizationStatus::Pending,
            )]),
        ),
        CriomeReply::SignatureRouteReceipt(SignatureRouteReceipt {
            request_slot: RequestSlot::new(authorization_request_slot()),
            routed_to: RoutedTo::new(host("balboa")),
        }),
        CriomeReply::SignatureSubmissionReceipt(SignatureSubmissionReceipt {
            request_slot: RequestSlot::new(authorization_request_slot()),
            signer: Signer::new(developer("reviewer")),
        }),
        CriomeReply::ContractAdmitted(ContractAdmitted::new(ContractObjectDigest::new(
            contract_digest(),
        ))),
        CriomeReply::ContractFound(ContractFound {
            contract_object_digest: ContractObjectDigest::new(contract_digest()),
            contract: policy_contract(),
        }),
        CriomeReply::ContractMissing(ContractMissing::new(ContractObjectDigest::new(
            contract_digest(),
        ))),
        CriomeReply::ContractAdmissionRejected(ContractAdmissionRejected::new(
            AdmissionRejectionReason::new(ContractAdmissionRejectionReason::DuplicatePolicyMember),
        )),
        CriomeReply::AuthorizationEvaluated(AuthorizationEvaluated {
            contract_object_digest: ContractObjectDigest::new(contract_digest()),
            decision: Decision::new(EvaluationDecision::Rejected(
                EvaluationRejectionReason::QuorumShort(QuorumShortfall {
                    required: Required::new(RequiredSignatureThreshold::new(2)),
                    satisfied: Satisfied::new(RequiredSignatureThreshold::new(1)),
                }),
            )),
        }),
        CriomeReply::AuthorizedObjectUpdateSnapshot(AuthorizedObjectUpdateSnapshot::from_updates(
            vec![authorized_object_update()],
        )),
        CriomeReply::AuthorizedObjectUpdateRetracted(AuthorizedObjectUpdateRetracted::new(
            Token::new(authorized_object_update_token()),
        )),
        CriomeReply::AuthorizationObservationRetracted(AuthorizationObservationRetracted::new(
            ObservationToken::new(authorization_observation_token()),
        )),
        CriomeReply::SubscriptionRetracted(SubscriptionRetracted::new(SubscriptionToken::new(
            IdentitySubscriptionToken::new(Subscriber::new(agent("operator"))),
        ))),
        CriomeReply::Rejection(Rejection::new(RejectionDetail::new(
            RejectionReason::ReplayAttempted,
        ))),
    ];

    for reply in replies {
        assert_eq!(round_trip_reply(reply.clone()), reply);
    }
}

#[test]
fn identity_update_event_round_trips_through_length_prefixed_frame() {
    let receipt = IdentityReceipt {
        identity: persona("designer"),
        principal_status_role: PrincipalStatusRole::new(PrincipalStatus::Active),
    };
    let event = CriomeEvent::IdentityUpdate(IdentityUpdate::new(Receipt::new(receipt)));
    assert_eq!(round_trip_event(event.clone()), event);
}

#[test]
fn authorization_update_event_round_trips_through_length_prefixed_frame() {
    let event = CriomeEvent::AuthorizationUpdate(AuthorizationUpdate::new(State::new(
        authorization_state(AuthorizationStatus::Granted),
    )));
    assert_eq!(round_trip_event(event.clone()), event);
}

#[test]
fn authorized_object_update_event_round_trips_through_length_prefixed_frame() {
    let event = CriomeEvent::AuthorizedObjectUpdate(authorized_object_update());
    assert_eq!(round_trip_event(event.clone()), event);
}

#[test]
fn authorization_grant_carries_satisfied_policy_threshold() {
    let grant = authorization_grant();

    assert_eq!(
        grant.request_slot,
        RequestSlot::new(authorization_request_slot()),
    );
    assert_eq!(
        *grant.policy_satisfaction.payload().policy_class.payload(),
        AuthorizationPolicyClass::ComplexQuorum,
    );
    assert_eq!(
        grant
            .policy_satisfaction
            .payload()
            .required_signature_threshold
            .into_u16(),
        1,
    );
    assert_eq!(
        grant.policy_satisfaction.payload().satisfied_signers(),
        &[cluster("uranus")],
    );
}

#[test]
fn quorum_signed_surfaces_carry_attested_moment_stamps() {
    let source = std::fs::read_to_string("schema/lib.schema").expect("read schema");

    for required in [
        "StampedSignature StampedSignatureEnvelope",
        "(EvidenceSignatures (Vector StampedSignatureEnvelope))",
        "(AuthorizationGrantSignatures (Vec StampedSignatureEnvelope))",
    ] {
        assert!(
            source.contains(required),
            "schema missing stamped signature surface: {required}"
        );
    }
    assert!(
        source.contains("TimeSignature {\n    Signer\n    Envelope\n  }"),
        "time signatures must stay bare because they create AttestedMoment"
    );
}

#[test]
fn authorized_object_update_carries_references_not_payloads() {
    let source = std::fs::read_to_string("schema/lib.schema").expect("read schema");

    assert!(
        source.contains("AuthorizedObjectReference {\n    Component\n    Digest\n    Kind\n  }")
    );
    assert!(source.contains("Digest ObjectDigest"));
    assert!(source.contains(
        "AuthorizedObjectUpdate {\n    Object\n    ContractObjectDigest\n    Decision\n    Stamp\n  }"
    ));
    assert!(source.contains("Object AuthorizedObjectReference"));
    assert!(source.contains("Stamp AttestedMoment"));
    assert!(
        !source.contains("AuthorizedObjectUpdate {\n    Object\n    Contract\n"),
        "authorized object pulse must not carry inline contract payloads"
    );
}

#[test]
fn authorization_denial_distinguishes_policy_from_signer_refusal() {
    let policy_denial = AuthorizationDenied {
        request_slot: RequestSlot::new(authorization_request_slot()),
        denial_detail: DenialDetail::new(AuthorizationDenial {
            denial_source: DenialSource::new(AuthorizationDenialSource::Policy),
            denial_reason: DenialReason::new(AuthorizationDenialReason::PolicyRefused),
        }),
    };
    let signer_denial = AuthorizationDenied {
        request_slot: RequestSlot::new(authorization_request_slot()),
        denial_detail: DenialDetail::new(AuthorizationDenial {
            denial_source: DenialSource::new(AuthorizationDenialSource::Signers),
            denial_reason: DenialReason::new(AuthorizationDenialReason::SignerThresholdRejected),
        }),
    };

    assert_ne!(policy_denial, signer_denial);
    assert_eq!(
        round_trip_reply(CriomeReply::AuthorizationDenied(policy_denial.clone())),
        CriomeReply::AuthorizationDenied(policy_denial)
    );
    assert_eq!(
        round_trip_reply(CriomeReply::AuthorizationDenied(signer_denial.clone())),
        CriomeReply::AuthorizationDenied(signer_denial)
    );
}

#[test]
fn root_request_round_trips_through_nota_text() {
    round_trip_nota(
        CriomeRequest::LookupIdentity(IdentityLookup::new(persona("designer"))),
        "(LookupIdentity (Persona designer))",
    );
}

#[test]
fn root_reply_round_trips_through_nota_text() {
    round_trip_nota(
        CriomeReply::VerificationResult(VerificationResult::new(
            VerificationDecision::UnknownSigner,
            None,
            None,
        )),
        "(VerificationResult (UnknownSigner None None))",
    );
}

#[test]
fn signature_scheme_is_bls_only() {
    let source = std::fs::read_to_string("src/schema/lib.rs").expect("read generated schema");

    assert!(source.contains("Bls12_381MinPk"));
    assert!(source.contains("Bls12_381MinSig"));
    assert!(!source.contains("Ed25519"));
}

#[test]
fn contract_does_not_define_auth_proof() {
    let source = std::fs::read_to_string("src/lib.rs").expect("read source");

    assert!(!source.contains("AuthProof"));
}

#[test]
fn contract_crate_carries_no_daemon_runtime_or_storage() {
    let manifest = std::fs::read_to_string("Cargo.toml").expect("read manifest");
    let source = std::fs::read_to_string("src/lib.rs").expect("read source");

    for forbidden in ["kameo", "tokio", "redb", "sema", "ractor"] {
        assert!(!manifest.contains(forbidden));
        assert!(!source.contains(forbidden));
    }
}

#[test]
fn contract_crate_carries_no_meta_class_operations() {
    let source = std::fs::read_to_string("src/lib.rs").expect("read source");

    for forbidden in [
        "SubmitPassphrase",
        "RegisterPolicy",
        "RegisterPeer",
        "RetractPeer",
        "RequestMetaApproval",
        "MetaApprovalReply",
    ] {
        assert!(
            !source.contains(forbidden),
            "meta operation leaked: {forbidden}"
        );
    }
}

#[test]
fn contract_crate_carries_no_database_action_mirror() {
    let manifest = std::fs::read_to_string("Cargo.toml").expect("read manifest");
    let source = std::fs::read_to_string("src/lib.rs").expect("read source");

    for forbidden in ["AuthorizedSignalVerb", "SemaOperation", "ToSemaOperation"] {
        assert!(
            !source.contains(forbidden),
            "database action mirror leaked: {forbidden}"
        );
    }
    assert!(!manifest.contains("signal-sema"));
}
