use nota::{NotaDecode, NotaEncode, NotaSource};
use signal_criome::{
    ActiveInterceptPolicies, ApprovalAuditSource, ArchiveAttestationRequest, Attestation,
    AttestationReceipt, AttestedMoment, AttestedMomentProposition, AuditContext,
    AuthorizationDenial, AuthorizationDenialReason, AuthorizationDenialSource, AuthorizationDenied,
    AuthorizationEvaluated, AuthorizationEvaluation, AuthorizationExpired, AuthorizationGrant,
    AuthorizationObservation, AuthorizationObservationRetracted, AuthorizationObservationSnapshot,
    AuthorizationObservationToken, AuthorizationPending, AuthorizationPolicyClass,
    AuthorizationPolicySatisfaction, AuthorizationRejection, AuthorizationRequestSlot,
    AuthorizationScope, AuthorizationStateRecord, AuthorizationStatus, AuthorizationUnavailable,
    AuthorizationUpdate, AuthorizationVerification, AuthorizedObjectInterest, AuthorizedObjectKind,
    AuthorizedObjectObservation, AuthorizedObjectReference, AuthorizedObjectUpdate,
    AuthorizedObjectUpdateRetracted, AuthorizedObjectUpdateSnapshot, AuthorizedObjectUpdateToken,
    BlsPublicKey, BlsSignature, ChannelGrantAttestationRequest, CoSignatureExpectation,
    ComponentKind, ComponentRelease, Composition, CompositionDigest, ContentPurpose,
    ContentReference, Contract, ContractAdmissionRejected, ContractAdmissionRejectionReason,
    ContractAdmitted, ContractDigest, ContractFound, ContractMissing, ContractName,
    ContractOperationHead, ContractParent, CriomeEvent, CriomeFrame as Frame,
    CriomeFrameBody as FrameBody, CriomeReply, CriomeRequest, EscalationTarget, EvaluationDecision,
    EvaluationRejectionReason, Evidence, ExpiryAction, FoundedRoot, FoundingConveyance,
    FoundingConveyanceOutcome, FoundingConveyanceReceipt, FoundingMember, FoundingProposal,
    FoundingSignature, FoundingSignatureReturn, GenesisDomainTag, Identity, IdentityLookup,
    IdentityReceipt, IdentityRegistration, IdentityRevocation, IdentitySnapshot,
    IdentitySubscription, IdentitySubscriptionToken, IdentityUpdate, InterceptPolicy,
    InterceptPolicyIdentifier, InterceptPolicyProposal, InterceptPolicyWindow,
    InterceptTargetSelector, KeyPurpose, MentciSessionSlot, NodePublicKey,
    NodePublicKeyObservation, ObjectCoSignature, ObjectDigest, OperationDigest,
    ParkedAuthorization, ParkedAuthorizationObservation, ParkedAuthorizationSnapshot,
    ParkedRequestIdentifier, ParkedRequestOutcome, ParkedRequestResolution, ParkedRequestSnapshot,
    ParkedSpiritRequest, PolicyDurationNanos, PolicyMember, PolicyOverlapMode, PolicyPriority,
    PrincipalName, PrincipalStatus, PublicKeyFingerprint, QuorumConflict, QuorumProposal,
    QuorumRoundIdentifier, QuorumRoundState, QuorumRoundStatus, QuorumShortfall, QuorumVote,
    QuorumVoteSolicitation, RawSpiritOperationPayload, Rejection, RejectionReason, ReplayNonce,
    RequiredSignatureThreshold, RootAnchorDigest, RootFoundingStatement, RootGenesis, RoundPhase,
    Rule, SignReceipt, SignRequest, SignalCallAuthorization, SignatureAuthorizationResult,
    SignatureEnvelope, SignatureRouteReceipt, SignatureScheme, SignatureSolicitation,
    SignatureSolicitationRoute, SignatureSubmission, SignatureSubmissionReceipt,
    SpiritAuthorizationContext, SpiritOperationName, SpiritOperationNames, SpiritProcessKey,
    StampedSignatureEnvelope, SubscriptionRetracted, Threshold, TimeSignature, TimeWindow,
    TimestampNanos, VerificationDecision, VerificationResult, VerifyRequest, WorkflowDigest,
    WorkflowGuard, WorkflowProvenanceDigest, WorkflowReceipt,
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
    AuthorizationObservationToken::new(authorization_request_slot())
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
            source: AuthorizationDenialSource::Signers,
            reason: AuthorizationDenialReason::SignatureRejected,
        }),
    )
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

fn composition_digest(name: &str) -> CompositionDigest {
    CompositionDigest::from_bytes(name.as_bytes())
}

fn workflow_digest() -> WorkflowDigest {
    WorkflowDigest::from_bytes(b"guardian workflow")
}

fn workflow_provenance_digest() -> WorkflowProvenanceDigest {
    WorkflowProvenanceDigest::from_bytes(b"guardian workflow provenance")
}

fn attested_moment() -> AttestedMoment {
    AttestedMoment::new(
        AttestedMomentProposition::new(
            TimeWindow {
                opens_at: TimestampNanos::new(10),
                closes_at: TimestampNanos::new(20),
            },
            RequiredSignatureThreshold::new(1),
            vec![developer("timekeeper")],
        ),
        vec![TimeSignature {
            signer: developer("timekeeper"),
            envelope: envelope(),
        }],
    )
}

fn quorum_round_identifier() -> QuorumRoundIdentifier {
    QuorumRoundIdentifier::new("quorum-round-1")
}

fn attested_moment_proposition() -> AttestedMomentProposition {
    AttestedMomentProposition::new(
        TimeWindow {
            opens_at: TimestampNanos::new(10),
            closes_at: TimestampNanos::new(20),
        },
        RequiredSignatureThreshold::new(2),
        vec![host("mirror-alpha"), host("mirror-beta")],
    )
}

fn quorum_proposal() -> QuorumProposal {
    QuorumProposal {
        round: quorum_round_identifier(),
        phase: RoundPhase::Request,
        contract: contract_digest(),
        object: authorized_object_reference(),
        window: TimeWindow {
            opens_at: TimestampNanos::new(10),
            closes_at: TimestampNanos::new(20),
        },
    }
}

fn quorum_vote_solicitation() -> QuorumVoteSolicitation {
    QuorumVoteSolicitation {
        round: quorum_round_identifier(),
        phase: RoundPhase::Request,
        contract: contract_digest(),
        object: authorized_object_reference(),
        proposition: attested_moment_proposition(),
        originator: host("mirror-alpha"),
    }
}

fn quorum_vote() -> QuorumVote {
    QuorumVote {
        round: quorum_round_identifier(),
        phase: RoundPhase::Request,
        voter: host("mirror-beta"),
        operation_signature: envelope(),
        time_signature: envelope(),
    }
}

fn quorum_round_state() -> QuorumRoundState {
    QuorumRoundState {
        round: quorum_round_identifier(),
        phase: RoundPhase::Request,
        contract: contract_digest(),
        status: QuorumRoundStatus::Authorized,
        gathered: RequiredSignatureThreshold::new(2),
        required: RequiredSignatureThreshold::new(2),
        authorized_evidence: Some(evidence()),
    }
}

fn quorum_conflict() -> QuorumConflict {
    QuorumConflict::new(
        contract_digest(),
        ContractOperationHead::new("head-1"),
        authorized_object_reference(),
    )
}

fn node_public_key() -> NodePublicKey {
    NodePublicKey::new(BlsPublicKey::new("node-master-pubkey"))
}

fn founding_member(name: &str) -> FoundingMember {
    FoundingMember::new(
        host(name),
        BlsPublicKey::new(format!("{name}-master-pubkey")),
    )
}

fn root_genesis() -> RootGenesis {
    RootGenesis::new(
        Contract::root(Rule::threshold(Threshold::new(
            RequiredSignatureThreshold::new(2),
            vec![
                PolicyMember::key_member(host("mirror-alpha")),
                PolicyMember::key_member(host("mirror-beta")),
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

fn founding_anchor() -> RootAnchorDigest {
    root_genesis().anchor().expect("genesis anchor")
}

fn founding_proposal() -> FoundingProposal {
    FoundingProposal {
        genesis: root_genesis(),
        initiator: host("mirror-alpha"),
    }
}

fn founding_signature_return() -> FoundingSignatureReturn {
    FoundingSignatureReturn {
        anchor: founding_anchor(),
        signature: FoundingSignature::new(host("mirror-beta"), envelope()),
    }
}

fn founded_root() -> FoundedRoot {
    FoundedRoot {
        genesis: root_genesis(),
        signatures: vec![
            FoundingSignature::new(host("mirror-alpha"), envelope()),
            FoundingSignature::new(host("mirror-beta"), envelope()),
        ],
    }
}

fn founding_conveyance_receipt() -> FoundingConveyanceReceipt {
    FoundingConveyanceReceipt {
        anchor: founding_anchor(),
        outcome: FoundingConveyanceOutcome::RootFounded,
    }
}

fn policy_contract() -> Contract {
    Contract::root(Rule::threshold(Threshold::new(
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

fn workflow_receipt() -> WorkflowReceipt {
    WorkflowReceipt {
        workflow: workflow_digest(),
        operation: operation_digest(),
        outcome: EvaluationDecision::Authorized,
        provenance: workflow_provenance_digest(),
    }
}

fn object_co_signature() -> ObjectCoSignature {
    ObjectCoSignature {
        object: authorized_object_reference(),
        signer: cluster("prometheus"),
        signature: stamped_envelope(),
    }
}

fn authorized_object_update_token() -> AuthorizedObjectUpdateToken {
    AuthorizedObjectUpdateToken {
        subscriber: agent("operator"),
        interest: AuthorizedObjectInterest::Component(ComponentKind::Spirit),
    }
}

fn authorized_object_reference() -> AuthorizedObjectReference {
    AuthorizedObjectReference {
        component: ComponentKind::Spirit,
        digest: operation_digest().object_digest().clone(),
        kind: AuthorizedObjectKind::Head,
    }
}

fn authorized_object_update() -> AuthorizedObjectUpdate {
    AuthorizedObjectUpdate {
        object: authorized_object_reference(),
        contract: contract_digest(),
        decision: EvaluationDecision::Authorized,
        stamp: attested_moment(),
    }
}

fn authorization_evaluation() -> AuthorizationEvaluation {
    AuthorizationEvaluation {
        contract: contract_digest(),
        object: authorized_object_reference(),
        evidence: evidence(),
    }
}

fn mentci_session_slot() -> MentciSessionSlot {
    MentciSessionSlot::new("mentci-session-1")
}

fn intercept_policy_identifier() -> InterceptPolicyIdentifier {
    InterceptPolicyIdentifier::new("intercept-policy-1")
}

fn spirit_process_key() -> SpiritProcessKey {
    SpiritProcessKey::new("spirit-process-main")
}

fn intercept_target() -> InterceptTargetSelector {
    InterceptTargetSelector::new(spirit_process_key())
}

fn spirit_operation_names() -> SpiritOperationNames {
    SpiritOperationNames::from_names(vec![
        SpiritOperationName::new("Record"),
        SpiritOperationName::new("ChangeRecord"),
    ])
}

fn intercept_policy() -> InterceptPolicy {
    InterceptPolicy {
        identifier: intercept_policy_identifier(),
        session_slot: mentci_session_slot(),
        target: intercept_target(),
        spirit_operation_names: spirit_operation_names(),
        window: InterceptPolicyWindow {
            starts_at: TimestampNanos::new(100),
            expires_at: TimestampNanos::new(200),
        },
        expiry_action: ExpiryAction::AutoApprove,
        priority: PolicyPriority::new(50),
    }
}

fn spirit_authorization_context() -> SpiritAuthorizationContext {
    SpiritAuthorizationContext {
        operation_name: SpiritOperationName::new("Record"),
        raw_payload: RawSpiritOperationPayload::new(
            "(Record (([(Technology Software)] Decision [policy text] High High Zero [])))",
        ),
        target_key: spirit_process_key(),
    }
}

fn parked_spirit_request() -> ParkedSpiritRequest {
    ParkedSpiritRequest {
        identifier: ParkedRequestIdentifier::new("parked-request-1"),
        matched_policy: intercept_policy_identifier(),
        session_slot: mentci_session_slot(),
        context: spirit_authorization_context(),
        parked_at: TimestampNanos::new(120),
        expires_at: TimestampNanos::new(200),
        expiry_action: ExpiryAction::AutoApprove,
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

fn assert_nota_round_trip<T>(value: T)
where
    T: NotaEncode + NotaDecode + PartialEq + std::fmt::Debug,
{
    let encoded = value.to_nota();
    let recovered = NotaSource::new(&encoded).parse::<T>().expect("decode nota");
    assert_eq!(recovered, value, "NOTA did not round-trip: {encoded}");
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
            content: content(ContentPurpose::SignedObject),
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
        CriomeRequest::ObserveParkedAuthorizations(ParkedAuthorizationObservation::new()),
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
        CriomeRequest::EvaluateAuthorization(authorization_evaluation()),
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
        CriomeRequest::ProposeQuorumAuthorization(quorum_proposal()),
        CriomeRequest::SolicitQuorumVote(quorum_vote_solicitation()),
        CriomeRequest::SubmitQuorumVote(quorum_vote()),
        CriomeRequest::ObserveQuorumRound(signal_criome::QuorumRoundQuery::new(
            quorum_round_identifier(),
        )),
        CriomeRequest::ObserveNodePublicKey(NodePublicKeyObservation::new()),
        CriomeRequest::ConveyFounding(FoundingConveyance::Proposal(founding_proposal())),
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
            "ObserveParkedAuthorizations",
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
            "ProposeQuorumAuthorization",
            "SolicitQuorumVote",
            "SubmitQuorumVote",
            "ObserveQuorumRound",
            "ObserveNodePublicKey",
            "ConveyFounding",
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
        CriomeReply::AuthorizationObservationSnapshot(
            AuthorizationObservationSnapshot::from_states(vec![authorization_state(
                AuthorizationStatus::Pending,
            )]),
        ),
        CriomeReply::ParkedAuthorizationSnapshot(ParkedAuthorizationSnapshot::from_parked(vec![
            ParkedAuthorization::from_evaluation(
                authorization_request_slot(),
                authorization_evaluation(),
            ),
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
        CriomeReply::AuthorizedObjectUpdateSnapshot(AuthorizedObjectUpdateSnapshot::from_updates(
            vec![authorized_object_update()],
        )),
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
        CriomeReply::QuorumRoundOpened(quorum_round_state()),
        CriomeReply::QuorumVoteSolicited(quorum_round_state()),
        CriomeReply::QuorumVoteAccepted(quorum_round_state()),
        CriomeReply::QuorumRoundObserved(quorum_round_state()),
        CriomeReply::NodePublicKey(node_public_key()),
        CriomeReply::QuorumConflict(quorum_conflict()),
        CriomeReply::FoundingConveyed(founding_conveyance_receipt()),
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
        grant.policy_satisfaction.satisfied_signers(),
        &[cluster("uranus")],
    );
}

#[test]
fn quorum_signed_surfaces_carry_attested_moment_stamps() {
    let source = std::fs::read_to_string("schema/lib.schema").expect("read schema");

    for required in [
        "signature.StampedSignatureEnvelope",
        "evidence_signatures.(Vector StampedSignatureEnvelope)",
        "authorization_grant_signatures.(Vec StampedSignatureEnvelope)",
    ] {
        assert!(
            source.contains(required),
            "schema missing stamped signature surface: {required}"
        );
    }
    assert!(
        source
            .contains("TimeSignature {\n    signer.Identity\n    envelope.SignatureEnvelope\n  }"),
        "time signatures must stay bare because they create AttestedMoment"
    );
}

#[test]
fn authorized_object_update_carries_references_not_payloads() {
    let source = std::fs::read_to_string("schema/lib.schema").expect("read schema");

    assert!(source.contains("AuthorizedObjectReference {\n    component.ComponentKind"));
    assert!(source.contains("    digest.ObjectDigest"));
    assert!(source.contains("AuthorizedObjectUpdate {\n    object.AuthorizedObjectReference"));
    assert!(source.contains("    contract.ContractDigest"));
    assert!(source.contains("    stamp.AttestedMoment"));
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
fn intercept_policy_and_parked_spirit_request_model_round_trips() {
    let proposal = InterceptPolicyProposal {
        session_slot: mentci_session_slot(),
        target: intercept_target(),
        spirit_operation_names: spirit_operation_names(),
        duration: PolicyDurationNanos::new(100),
        expiry_action: ExpiryAction::AutoApprove,
        priority: PolicyPriority::new(50),
        overlap_mode: PolicyOverlapMode::RejectSamePriorityOverlap,
    };
    let policies = ActiveInterceptPolicies::from_policies(vec![intercept_policy()]);
    let parked_requests = ParkedRequestSnapshot::from_requests(vec![parked_spirit_request()]);
    let manual_rejection = ParkedRequestResolution {
        identifier: ParkedRequestIdentifier::new("parked-request-1"),
        matched_policy: intercept_policy_identifier(),
        outcome: ParkedRequestOutcome::Rejected,
        audit_source: ApprovalAuditSource::Manual,
        resolved_at: TimestampNanos::new(130),
    };
    let automatic_approval = ParkedRequestResolution {
        identifier: ParkedRequestIdentifier::new("parked-request-1"),
        matched_policy: intercept_policy_identifier(),
        outcome: ParkedRequestOutcome::Approved,
        audit_source: ApprovalAuditSource::Automatic,
        resolved_at: TimestampNanos::new(200),
    };

    assert_eq!(proposal.spirit_operation_names.names().len(), 2);
    assert_eq!(policies.policies(), &[intercept_policy()]);
    assert_eq!(parked_requests.requests(), &[parked_spirit_request()]);
    assert_nota_round_trip(proposal);
    assert_nota_round_trip(policies);
    assert_nota_round_trip(parked_requests);
    assert_nota_round_trip(manual_rejection);
    assert_nota_round_trip(automatic_approval);

    let source = std::fs::read_to_string("schema/lib.schema").expect("read schema");
    assert!(
        source.contains("not a")
            && source.contains("cryptographic or durable identity binding")
            && source.contains("Authority-binding remains"),
        "schema must keep the MVP target-key identity deferral explicit"
    );
}

#[test]
fn workflow_guard_contract_round_trips_through_frame_and_nota() {
    let contract = Contract::root(Rule::workflow(WorkflowGuard {
        workflow: workflow_digest(),
        executor: agent("guardian-runner"),
    }));
    let request = CriomeRequest::AdmitContract(contract.clone());

    assert_eq!(round_trip_request(request.clone()), request);
    assert_nota_round_trip(contract);
}

#[test]
fn composition_rule_uses_content_addressed_children() {
    let composition = Composition::all_of(vec![
        composition_digest("guardian-workflow-step"),
        composition_digest("psyche-escalation-step"),
    ]);
    let contract = Contract::root(Rule::composition(composition.clone()));

    assert_eq!(
        round_trip_request(CriomeRequest::AdmitContract(contract.clone())),
        CriomeRequest::AdmitContract(contract),
    );
    assert_nota_round_trip(composition);
}

#[test]
fn full_guard_decision_outcomes_round_trip() {
    for decision in [
        EvaluationDecision::Authorized,
        EvaluationDecision::Deferred,
        EvaluationDecision::NonJudgement,
        EvaluationDecision::escalate(EscalationTarget::Psyche),
        EvaluationDecision::escalate(EscalationTarget::Workflow(workflow_digest())),
        EvaluationDecision::escalate(EscalationTarget::smarter_agent(agent("guardian"))),
    ] {
        let reply = CriomeReply::AuthorizationEvaluated(AuthorizationEvaluated {
            contract: contract_digest(),
            decision,
        });
        assert_eq!(round_trip_reply(reply.clone()), reply);
    }
}

#[test]
fn workflow_receipts_and_peer_cosignatures_ride_evidence() {
    let evidence = evidence()
        .with_workflow_receipts(vec![workflow_receipt()])
        .with_object_co_signatures(vec![object_co_signature()]);

    assert_eq!(evidence.workflow_receipts(), &[workflow_receipt()]);
    assert_eq!(evidence.object_co_signatures(), &[object_co_signature()]);

    let evaluation = AuthorizationEvaluation {
        contract: contract_digest(),
        object: authorized_object_reference(),
        evidence,
    };
    let request = CriomeRequest::EvaluateAuthorization(evaluation.clone());

    assert_eq!(round_trip_request(request.clone()), request);
    assert_nota_round_trip(evaluation);
}

#[test]
fn co_signature_expectation_tracks_expected_and_observed_peer_signers() {
    let expectation = CoSignatureExpectation::new(
        authorized_object_reference(),
        vec![cluster("local"), cluster("prometheus")],
        vec![cluster("local")],
    );

    assert_eq!(
        expectation.expected_signers(),
        &[cluster("local"), cluster("prometheus")],
    );
    assert_eq!(expectation.observed_signers(), &[cluster("local")]);
    assert_nota_round_trip(expectation);
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
fn parent_link_and_root_founding_surfaces_round_trip() {
    // The parent link re-digests the contract: a Root sentinel and a child from
    // the same rule are different content addresses, and both survive the wire.
    let root = Contract::root(Rule::EscalateToPsyche);
    let child = Contract::child(Rule::EscalateToPsyche, contract_digest());
    assert_eq!(root.parent(), &ContractParent::Root);
    assert_ne!(
        root.digest().expect("root digest"),
        child.digest().expect("child digest"),
        "the parent link must be part of the content address",
    );
    assert_nota_round_trip(root);
    assert_nota_round_trip(child);

    // The founding certificate: the anchor commits to the founding key-set, and
    // the attached founding signature + its preimage statement round-trip.
    let genesis = root_genesis();
    assert_eq!(genesis.founding_keys().len(), 2);
    let anchor = genesis.anchor().expect("anchor");
    let statement =
        RootFoundingStatement::new(anchor.clone(), GenesisDomainTag::CriomeRootFoundingV1);
    statement.preimage_digest().expect("preimage digest");
    assert_eq!(
        GenesisDomainTag::CriomeRootFoundingV1.domain_separator(),
        "CRIOME-ROOT-FOUNDING-V1",
    );

    assert_nota_round_trip(genesis);
    assert_nota_round_trip(statement);
    assert_nota_round_trip(FoundingSignature::new(host("mirror-alpha"), envelope()));
    assert_nota_round_trip(anchor);
    assert_nota_round_trip(RootAnchorDigest::from_bytes(b"anchor fixture"));

    // Node public-key observation + the refusal reply.
    assert_nota_round_trip(node_public_key());
    assert_nota_round_trip(quorum_conflict());
    assert_nota_round_trip(Rejection::new(RejectionReason::OutsideTimeWindow));

    // Founding conveyance: each of the three movements (proposal out, signature
    // back, finished root out) and the receipt round-trip on the wire, so a
    // multi-node cohort can gather a unanimous root across peers.
    assert_nota_round_trip(FoundingConveyance::Proposal(founding_proposal()));
    assert_nota_round_trip(FoundingConveyance::Signature(founding_signature_return()));
    assert_nota_round_trip(FoundingConveyance::Founded(founded_root()));
    assert_nota_round_trip(founding_conveyance_receipt());
}

#[test]
fn quorum_round_key_is_phase_aware() {
    // Round 1 (Request) and round 2 (Commit) over the SAME object get distinct
    // durable round keys, so their signatures are never interchangeable.
    let object = operation_digest().object_digest().clone();
    let request = QuorumRoundIdentifier::for_phase(&object, RoundPhase::Request);
    let commit = QuorumRoundIdentifier::for_phase(&object, RoundPhase::Commit);
    assert_ne!(request, commit);
    assert_eq!(
        QuorumRoundIdentifier::for_operation(&object),
        request,
        "for_operation is the round-1 (Request) convenience",
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
