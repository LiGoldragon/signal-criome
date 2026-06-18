use nota_next::{NotaDecode, NotaEncode, NotaSource};
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
        digest: ObjectDigest::from_bytes(b"contract fixture"),
        purpose,
        schema_version: PrincipalName::new("signal-criome/0"),
    }
}

fn audit(purpose: ContentPurpose) -> AuditContext {
    AuditContext {
        purpose,
        audience: PrincipalName::new("persona-engine"),
        policy_version: PrincipalName::new("policy-v1"),
        nonce: ReplayNonce::new("nonce-1"),
    }
}

fn envelope() -> SignatureEnvelope {
    SignatureEnvelope {
        scheme: SignatureScheme::Bls12_381MinPk,
        public_key: BlsPublicKey::new("bls-pubkey-fixture"),
        signature: BlsSignature::new("bls-signature-fixture"),
    }
}

fn stamped_envelope() -> StampedSignatureEnvelope {
    StampedSignatureEnvelope {
        stamp: attested_moment(),
        envelope: envelope(),
    }
}

fn attestation(purpose: ContentPurpose) -> Attestation {
    Attestation {
        content: content(purpose),
        signer: developer("operator"),
        envelope: envelope(),
        issued_at: TimestampNanos::new(1),
        expires_at: Some(TimestampNanos::new(2)),
        audit_context: audit(purpose),
    }
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
    SignalCallAuthorization {
        request_digest: ObjectDigest::from_bytes(b"signal-lojix request"),
        contract: contract_name(),
        operation: contract_operation_head(),
        scope: authorization_scope(),
        requester: developer("operator"),
        nonce: ReplayNonce::new("authorization-nonce-1"),
        expires_at: Some(TimestampNanos::new(10)),
    }
}

fn authorization_observation_token() -> AuthorizationObservationToken {
    AuthorizationObservationToken::new(authorization_request_slot())
}

fn authorization_grant() -> AuthorizationGrant {
    AuthorizationGrant {
        request_slot: authorization_request_slot(),
        authorized_object_digest: ObjectDigest::from_bytes(b"signal-lojix request"),
        authorized_contract: contract_name(),
        authorized_operation: contract_operation_head(),
        authorization_scope: authorization_scope(),
        policy_satisfaction: AuthorizationPolicySatisfaction {
            policy_class: AuthorizationPolicyClass::ComplexQuorum,
            required_signature_threshold: RequiredSignatureThreshold::new(1),
            satisfied_signers: vec![cluster("uranus")],
        },
        signature_result: SignatureAuthorizationResult::RequiredSignaturesSatisfied,
        signatures: vec![stamped_envelope()],
        issued_by: cluster("uranus"),
        issued_at: TimestampNanos::new(11),
        expires_at: Some(TimestampNanos::new(12)),
    }
}

fn authorization_state(status: AuthorizationStatus) -> AuthorizationStateRecord {
    AuthorizationStateRecord {
        request_slot: authorization_request_slot(),
        request_digest: ObjectDigest::from_bytes(b"signal-lojix request"),
        status,
        missing_authorities: vec![developer("reviewer")],
        grant: (status == AuthorizationStatus::Granted).then(authorization_grant),
        denial: (status == AuthorizationStatus::Denied).then_some(AuthorizationDenial {
            source: AuthorizationDenialSource::Signers,
            reason: AuthorizationDenialReason::SignatureRejected,
        }),
    }
}

fn signature_solicitation() -> SignatureSolicitation {
    SignatureSolicitation {
        request_slot: authorization_request_slot(),
        request_digest: ObjectDigest::from_bytes(b"signal-lojix request"),
        contract: contract_name(),
        operation: contract_operation_head(),
        scope: authorization_scope(),
        requester: developer("operator"),
        required_signer: developer("reviewer"),
    }
}

fn contract_digest() -> ContractDigest {
    ContractDigest::from_bytes(b"contract fixture")
}

fn operation_digest() -> OperationDigest {
    OperationDigest::from_bytes(b"operation fixture")
}

fn attested_moment() -> AttestedMoment {
    AttestedMoment {
        proposition: AttestedMomentProposition {
            window: TimeWindow {
                opens_at: TimestampNanos::new(10),
                closes_at: TimestampNanos::new(20),
            },
            required_signatures: RequiredSignatureThreshold::new(1),
            authorities: vec![developer("timekeeper")],
        },
        signatures: vec![TimeSignature {
            signer: developer("timekeeper"),
            envelope: envelope(),
        }],
    }
}

fn policy_contract() -> Contract {
    Contract::new(Rule::threshold(Threshold {
        required_signatures: RequiredSignatureThreshold::new(2),
        members: vec![
            PolicyMember::key_member(developer("operator")),
            PolicyMember::key_member(developer("reviewer")),
        ],
    }))
}

fn evidence() -> Evidence {
    Evidence {
        component: ComponentKind::Spirit,
        operation: operation_digest(),
        stamp: attested_moment(),
        signatures: vec![stamped_envelope()],
        agreements: Vec::new(),
    }
}

fn authorized_object_update_token() -> AuthorizedObjectUpdateToken {
    AuthorizedObjectUpdateToken::new(agent("operator"))
}

fn authorized_object_update() -> AuthorizedObjectUpdate {
    AuthorizedObjectUpdate {
        object: AuthorizedObjectReference {
            component: ComponentKind::Spirit,
            digest: ObjectDigest::from_bytes(b"operation fixture"),
            kind: AuthorizedObjectKind::Operation,
        },
        contract: contract_digest(),
        decision: EvaluationDecision::Authorized,
        stamp: attested_moment(),
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
        CriomeRequest::Sign(SignRequest {
            content: content(ContentPurpose::SignedObject),
            signer: developer("operator"),
            audit_context: audit(ContentPurpose::SignedObject),
            expires_at: None,
        }),
        CriomeRequest::VerifyAttestation(VerifyRequest {
            attestation: attestation(ContentPurpose::SignedObject),
            content: content(ContentPurpose::SignedObject),
        }),
        CriomeRequest::RegisterIdentity(IdentityRegistration {
            identity: persona("designer"),
            public_key: BlsPublicKey::new("designer-public-key"),
            fingerprint: PublicKeyFingerprint::new("fingerprint-designer"),
            purpose: KeyPurpose::PersonaRequest,
            admission: None,
        }),
        CriomeRequest::RevokeIdentity(IdentityRevocation {
            identity: persona("designer"),
            fingerprint: PublicKeyFingerprint::new("fingerprint-designer"),
            reason: PrincipalName::new("retired"),
        }),
        CriomeRequest::LookupIdentity(IdentityLookup::new(host("prometheus"))),
        CriomeRequest::AttestArchive(ArchiveAttestationRequest {
            release: ComponentRelease {
                component: PrincipalName::new("persona-router"),
                artifact: ObjectDigest::from_bytes(b"closure"),
                authorized_by: developer("operator"),
            },
            audit_context: audit(ContentPurpose::Archive),
        }),
        CriomeRequest::AttestChannelGrant(ChannelGrantAttestationRequest {
            grant_content: content(ContentPurpose::ChannelGrant),
            source: persona("mind"),
            audit_context: audit(ContentPurpose::ChannelGrant),
        }),
        CriomeRequest::AttestAuthorization(signal_criome::AuthorizationAttestationRequest {
            authorization_content: content(ContentPurpose::Authorization),
            source: persona("mind"),
            audit_context: audit(ContentPurpose::Authorization),
        }),
        CriomeRequest::AuthorizeSignalCall(signal_call_authorization()),
        CriomeRequest::ObserveAuthorization(AuthorizationObservation::new(
            authorization_request_slot(),
        )),
        CriomeRequest::VerifyAuthorization(AuthorizationVerification {
            request_digest: ObjectDigest::from_bytes(b"signal-lojix request"),
            authorization: authorization_grant(),
        }),
        CriomeRequest::RouteSignatureRequest(SignatureSolicitationRoute {
            solicitation: signature_solicitation(),
            routed_to: host("balboa"),
        }),
        CriomeRequest::SubmitSignature(SignatureSubmission {
            request_slot: authorization_request_slot(),
            signer: developer("reviewer"),
            signature: stamped_envelope(),
        }),
        CriomeRequest::RejectAuthorization(AuthorizationRejection {
            request_slot: authorization_request_slot(),
            rejector: developer("reviewer"),
            reason: AuthorizationDenialReason::SignatureRejected,
        }),
        CriomeRequest::AdmitContract(policy_contract()),
        CriomeRequest::LookupContract(contract_digest()),
        CriomeRequest::EvaluateAuthorization(AuthorizationEvaluation {
            contract: contract_digest(),
            evidence: evidence(),
        }),
        CriomeRequest::ObserveAuthorizedObjects(AuthorizedObjectObservation {
            subscriber: agent("operator"),
            interest: AuthorizedObjectInterest::Component(ComponentKind::Spirit),
        }),
        CriomeRequest::AuthorizedObjectUpdateRetraction(authorized_object_update_token()),
        CriomeRequest::SubscribeIdentityUpdates(IdentitySubscription::new(agent("operator"))),
        CriomeRequest::IdentitySubscriptionRetraction(IdentitySubscriptionToken::new(agent(
            "operator",
        ))),
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
        status: PrincipalStatus::Active,
    };
    let replies = vec![
        CriomeReply::SignReceipt(SignReceipt {
            attestation: attestation(ContentPurpose::SignedObject),
            issued_at: TimestampNanos::new(1),
        }),
        CriomeReply::VerificationResult(VerificationResult {
            decision: VerificationDecision::Valid,
            identity: Some(developer("operator")),
            expires_at: Some(TimestampNanos::new(2)),
        }),
        CriomeReply::IdentityReceipt(receipt.clone()),
        CriomeReply::IdentitySnapshot(IdentitySnapshot::new(vec![receipt.clone()])),
        CriomeReply::AttestationReceipt(AttestationReceipt::new(attestation(
            ContentPurpose::Archive,
        ))),
        CriomeReply::AuthorizationPending(AuthorizationPending {
            request_slot: authorization_request_slot(),
            request_digest: ObjectDigest::from_bytes(b"signal-lojix request"),
            missing_authorities: vec![developer("reviewer")],
            observation_token: authorization_observation_token(),
        }),
        CriomeReply::AuthorizationGranted(authorization_grant()),
        CriomeReply::AuthorizationDenied(AuthorizationDenied {
            request_slot: authorization_request_slot(),
            denial: AuthorizationDenial {
                source: AuthorizationDenialSource::Policy,
                reason: AuthorizationDenialReason::SignatureScopeMismatch,
            },
        }),
        CriomeReply::AuthorizationExpired(AuthorizationExpired {
            request_slot: authorization_request_slot(),
            expired_at: TimestampNanos::new(13),
        }),
        CriomeReply::AuthorizationUnavailable(AuthorizationUnavailable {
            request_slot: authorization_request_slot(),
            reason: PrincipalName::new("criome-peer-unreachable"),
        }),
        CriomeReply::AuthorizationObservationSnapshot(AuthorizationObservationSnapshot::new(vec![
            authorization_state(AuthorizationStatus::Pending),
        ])),
        CriomeReply::SignatureRouteReceipt(SignatureRouteReceipt {
            request_slot: authorization_request_slot(),
            routed_to: host("balboa"),
        }),
        CriomeReply::SignatureSubmissionReceipt(SignatureSubmissionReceipt {
            request_slot: authorization_request_slot(),
            signer: developer("reviewer"),
        }),
        CriomeReply::ContractAdmitted(ContractAdmitted::new(contract_digest())),
        CriomeReply::ContractFound(ContractFound {
            digest: contract_digest(),
            contract: policy_contract(),
        }),
        CriomeReply::ContractMissing(ContractMissing::new(contract_digest())),
        CriomeReply::ContractAdmissionRejected(ContractAdmissionRejected::new(
            ContractAdmissionRejectionReason::DuplicatePolicyMember,
        )),
        CriomeReply::AuthorizationEvaluated(AuthorizationEvaluated {
            contract: contract_digest(),
            decision: EvaluationDecision::Rejected(EvaluationRejectionReason::QuorumShort(
                QuorumShortfall {
                    required: RequiredSignatureThreshold::new(2),
                    satisfied: RequiredSignatureThreshold::new(1),
                },
            )),
        }),
        CriomeReply::AuthorizedObjectUpdateSnapshot(AuthorizedObjectUpdateSnapshot::new(vec![
            authorized_object_update(),
        ])),
        CriomeReply::AuthorizedObjectUpdateRetracted(AuthorizedObjectUpdateRetracted::new(
            authorized_object_update_token(),
        )),
        CriomeReply::AuthorizationObservationRetracted(AuthorizationObservationRetracted::new(
            authorization_observation_token(),
        )),
        CriomeReply::SubscriptionRetracted(SubscriptionRetracted::new(
            IdentitySubscriptionToken::new(agent("operator")),
        )),
        CriomeReply::Rejection(Rejection::new(RejectionReason::ReplayAttempted)),
    ];

    for reply in replies {
        assert_eq!(round_trip_reply(reply.clone()), reply);
    }
}

#[test]
fn identity_update_event_round_trips_through_length_prefixed_frame() {
    let receipt = IdentityReceipt {
        identity: persona("designer"),
        status: PrincipalStatus::Active,
    };
    let event = CriomeEvent::IdentityUpdate(IdentityUpdate::new(receipt));
    assert_eq!(round_trip_event(event.clone()), event);
}

#[test]
fn authorization_update_event_round_trips_through_length_prefixed_frame() {
    let event = CriomeEvent::AuthorizationUpdate(AuthorizationUpdate::new(authorization_state(
        AuthorizationStatus::Granted,
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

    assert_eq!(grant.request_slot, authorization_request_slot());
    assert_eq!(
        grant.policy_satisfaction.policy_class,
        AuthorizationPolicyClass::ComplexQuorum,
    );
    assert_eq!(
        grant
            .policy_satisfaction
            .required_signature_threshold
            .into_u16(),
        1,
    );
    assert_eq!(
        grant.policy_satisfaction.satisfied_signers,
        vec![cluster("uranus")],
    );
}

#[test]
fn quorum_signed_surfaces_carry_attested_moment_stamps() {
    let source = std::fs::read_to_string("schema/lib.schema").expect("read schema");

    for required in [
        "signature StampedSignatureEnvelope",
        "signatures (Vector StampedSignatureEnvelope)",
        "signatures (Vec StampedSignatureEnvelope)",
    ] {
        assert!(
            source.contains(required),
            "schema missing stamped signature surface: {required}"
        );
    }
    assert!(
        source
            .contains("TimeSignature {\n    signer Identity\n    envelope SignatureEnvelope\n  }"),
        "time signatures must stay bare because they create AttestedMoment"
    );
}

#[test]
fn authorized_object_update_carries_references_not_payloads() {
    let source = std::fs::read_to_string("schema/lib.schema").expect("read schema");

    assert!(source.contains("AuthorizedObjectReference {\n    component ComponentKind"));
    assert!(source.contains("    digest ObjectDigest"));
    assert!(source.contains("AuthorizedObjectUpdate {\n    object AuthorizedObjectReference"));
    assert!(source.contains("    contract ContractDigest"));
    assert!(source.contains("    stamp AttestedMoment"));
    assert!(
        !source.contains("AuthorizedObjectUpdate {\n    object Contract"),
        "authorized object pulse must not carry inline contract payloads"
    );
}

#[test]
fn authorization_denial_distinguishes_policy_from_signer_refusal() {
    let policy_denial = AuthorizationDenied {
        request_slot: authorization_request_slot(),
        denial: AuthorizationDenial {
            source: AuthorizationDenialSource::Policy,
            reason: AuthorizationDenialReason::PolicyRefused,
        },
    };
    let signer_denial = AuthorizationDenied {
        request_slot: authorization_request_slot(),
        denial: AuthorizationDenial {
            source: AuthorizationDenialSource::Signers,
            reason: AuthorizationDenialReason::SignerThresholdRejected,
        },
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
        CriomeReply::VerificationResult(VerificationResult {
            decision: VerificationDecision::UnknownSigner,
            identity: None,
            expires_at: None,
        }),
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
