use nota::{NotaDecode, NotaEncode, NotaSource};
use signal_criome::{
    ActiveInterceptPolicies, ActorIdentifier, ApprovalAuditSource, ArchiveAttestationRequest,
    Attestation, AttestationReceipt, AttestedMoment, AttestedMomentProposition, AuditContext,
    AuthorizationDenial, AuthorizationDenialReason, AuthorizationDenialSource, AuthorizationDenied,
    AuthorizationEvaluated, AuthorizationEvaluation, AuthorizationExpired, AuthorizationGrant,
    AuthorizationObservation, AuthorizationObservationRetracted, AuthorizationObservationSnapshot,
    AuthorizationObservationToken, AuthorizationPending, AuthorizationPolicyClass,
    AuthorizationPolicySatisfaction, AuthorizationRejection, AuthorizationRequestSlot,
    AuthorizationScope, AuthorizationStateRecord, AuthorizationStatus, AuthorizationUnavailable,
    AuthorizationVerification, AuthorizedObjectInterest, AuthorizedObjectKind,
    AuthorizedObjectObservation, AuthorizedObjectReference, AuthorizedObjectUpdate,
    AuthorizedObjectUpdateRetracted, AuthorizedObjectUpdateSnapshot, AuthorizedObjectUpdateToken,
    BlsPublicKey, BlsSignature, ChannelGrantAttestationRequest, CoSignatureExpectation,
    ComponentKind, ComponentRelease, Composition, CompositionDigest, ContentPurpose,
    ContentReference, Contract, ContractAdmissionRejected, ContractAdmissionRejectionReason,
    ContractAdmitted, ContractDigest, ContractFound, ContractMissing, ContractName,
    ContractOperationHead, ContractParent, CriomeDaemonConfiguration, CriomeFrame as Frame,
    CriomeFrameBody as FrameBody, CriomeReply, CriomeRequest, DaemonPath, EscalationTarget,
    EvaluationDecision, EvaluationRejectionReason, Evidence, ExpiryAction, FoundedRoot,
    FoundingConveyance, FoundingConveyanceOutcome, FoundingConveyanceReceipt, FoundingMember,
    FoundingProposal, FoundingSignature, FoundingSignatureReturn, GenesisDomainTag, Identity,
    IdentityLookup, IdentityReceipt, IdentityRegistration, IdentityRevocation, IdentitySnapshot,
    IdentitySubscription, IdentitySubscriptionToken, InterceptPolicy, InterceptPolicyIdentifier,
    InterceptPolicyProposal, InterceptPolicyWindow, InterceptTargetSelector, KeyPurpose,
    MentciSessionSlot, NodePublicKey, NodePublicKeyObservation, ObjectCoSignature, ObjectDigest,
    OperationDigest, ParkedAuthorization, ParkedAuthorizationObservation,
    ParkedAuthorizationSnapshot, ParkedRequestIdentifier, ParkedRequestOutcome,
    ParkedRequestResolution, ParkedRequestSnapshot, ParkedSpiritRequest, PeerActorRoute,
    PolicyDurationNanos, PolicyMember, PolicyOverlapMode, PolicyPriority, PrincipalName,
    PrincipalStatus, PublicKeyFingerprint, QuorumConflict, QuorumProposal, QuorumRoundIdentifier,
    QuorumRoundState, QuorumRoundStatus, QuorumShortfall, QuorumVote, QuorumVoteSolicitation,
    QuorumWindowNanos, RawSpiritOperationPayload, Rejection, RejectionReason, ReplayNonce,
    RequiredSignatureThreshold, RootAnchorDigest, RootFoundingStatement, RootGenesis, RoundPhase,
    RouterSubmissionConfiguration, Rule, SignReceipt, SignRequest, SignalCallAuthorization,
    SignatureAuthorizationResult, SignatureEnvelope, SignatureRouteReceipt, SignatureScheme,
    SignatureSolicitation, SignatureSolicitationRoute, SignatureSubmission,
    SignatureSubmissionReceipt, SpiritAuthorizationContext, SpiritOperationName,
    SpiritOperationNames, SpiritProcessKey, StampedSignatureEnvelope, SubscriptionRetracted,
    Threshold, TimeSignature, TimeWindow, TimestampNanos, VerificationDecision, VerificationResult,
    VerifyRequest, WorkflowDigest, WorkflowGuard, WorkflowProvenanceDigest, WorkflowReceipt,
};
use signal_frame::{
    ExchangeIdentifier, ExchangeLane, LaneSequence, NonEmpty, Reply, RequestPayload, SessionEpoch,
    SignalOperationHeads, SubReply,
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
        object_digest: ObjectDigest::from_bytes(b"contract fixture"),
        content_purpose: purpose,
        principal_name: PrincipalName::new("signal-criome/0"),
    }
}

fn audit(purpose: ContentPurpose) -> AuditContext {
    AuditContext {
        content_purpose: purpose,
        audience: PrincipalName::new("persona-engine"),
        policy_version: PrincipalName::new("policy-v1"),
        replay_nonce: ReplayNonce::new("nonce-1"),
    }
}

fn envelope() -> SignatureEnvelope {
    SignatureEnvelope {
        signature_scheme: SignatureScheme::Bls12_381MinPk,
        bls_public_key: BlsPublicKey::new("bls-pubkey-fixture"),
        bls_signature: BlsSignature::new("bls-signature-fixture"),
    }
}

fn stamped_envelope() -> StampedSignatureEnvelope {
    StampedSignatureEnvelope {
        attested_moment: attested_moment(),
        signature_envelope: envelope(),
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
    AuthorizationScope::new("deploy:zeus:CompleteHost")
}

fn contract_name() -> ContractName {
    ContractName::new("signal-lojix")
}

fn contract_operation_head() -> ContractOperationHead {
    ContractOperationHead::new("Deploy")
}

fn authorized_request_object() -> AuthorizedObjectReference {
    AuthorizedObjectReference {
        component_kind: ComponentKind::Lojix,
        object_digest: ObjectDigest::from_bytes(b"signal-lojix request"),
        authorized_object_kind: AuthorizedObjectKind::Operation,
    }
}

fn signal_call_authorization() -> SignalCallAuthorization {
    SignalCallAuthorization::new(
        authorized_request_object(),
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
        authorized_request_object(),
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
            authorization_denial_source: AuthorizationDenialSource::Signers,
            authorization_denial_reason: AuthorizationDenialReason::SignatureRejected,
        }),
    )
}

fn signature_solicitation() -> SignatureSolicitation {
    SignatureSolicitation {
        authorization_request_slot: authorization_request_slot(),
        object_digest: ObjectDigest::from_bytes(b"signal-lojix request"),
        contract_name: contract_name(),
        contract_operation_head: contract_operation_head(),
        authorization_scope: authorization_scope(),
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
            identity: developer("timekeeper"),
            signature_envelope: envelope(),
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
        attested_moment_proposition: attested_moment_proposition(),
        identity: host("mirror-alpha"),
    }
}

fn quorum_vote() -> QuorumVote {
    QuorumVote {
        quorum_round_identifier: quorum_round_identifier(),
        round_phase: RoundPhase::Request,
        identity: host("mirror-beta"),
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
        Contract::root(Rule::threshold_rule(Threshold::new(
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
        root_genesis: root_genesis(),
        identity: host("mirror-alpha"),
    }
}

fn founding_signature_return() -> FoundingSignatureReturn {
    FoundingSignatureReturn {
        root_anchor_digest: founding_anchor(),
        founding_signature: FoundingSignature::new(host("mirror-beta"), envelope()),
    }
}

fn founded_root() -> FoundedRoot {
    FoundedRoot {
        root_genesis: root_genesis(),
        founding_signature_vector: vec![
            FoundingSignature::new(host("mirror-alpha"), envelope()),
            FoundingSignature::new(host("mirror-beta"), envelope()),
        ],
    }
}

fn founding_conveyance_receipt() -> FoundingConveyanceReceipt {
    FoundingConveyanceReceipt {
        root_anchor_digest: founding_anchor(),
        founding_conveyance_outcome: FoundingConveyanceOutcome::RootFounded,
    }
}

fn policy_contract() -> Contract {
    Contract::root(Rule::threshold_rule(Threshold::new(
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
        workflow_digest: workflow_digest(),
        operation_digest: operation_digest(),
        evaluation_decision: EvaluationDecision::Authorized,
        workflow_provenance_digest: workflow_provenance_digest(),
    }
}

fn object_co_signature() -> ObjectCoSignature {
    ObjectCoSignature {
        authorized_object_reference: authorized_object_reference(),
        identity: cluster("prometheus"),
        stamped_signature_envelope: stamped_envelope(),
    }
}

fn authorized_object_update_token() -> AuthorizedObjectUpdateToken {
    AuthorizedObjectUpdateToken {
        identity: agent("operator"),
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
        intercept_policy_identifier: intercept_policy_identifier(),
        mentci_session_slot: mentci_session_slot(),
        intercept_target_selector: intercept_target(),
        spirit_operation_names: spirit_operation_names(),
        intercept_policy_window: InterceptPolicyWindow {
            starts_at: TimestampNanos::new(100),
            expires_at: TimestampNanos::new(200),
        },
        expiry_action: ExpiryAction::AutoApprove,
        policy_priority: PolicyPriority::new(50),
    }
}

fn spirit_authorization_context() -> SpiritAuthorizationContext {
    SpiritAuthorizationContext {
        spirit_operation_name: SpiritOperationName::new("Record"),
        raw_spirit_operation_payload: RawSpiritOperationPayload::new(
            "(Record (([(Technology Software)] Decision [policy text] High High Zero [])))",
        ),
        spirit_process_key: spirit_process_key(),
    }
}

fn parked_spirit_request() -> ParkedSpiritRequest {
    ParkedSpiritRequest {
        parked_request_identifier: ParkedRequestIdentifier::new("parked-request-1"),
        intercept_policy_identifier: intercept_policy_identifier(),
        mentci_session_slot: mentci_session_slot(),
        spirit_authorization_context: spirit_authorization_context(),
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
            content_reference: content(ContentPurpose::SignedObject),
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
            public_key_fingerprint: PublicKeyFingerprint::new("fingerprint-designer"),
            principal_name: PrincipalName::new("retired"),
        }),
        CriomeRequest::LookupIdentity(IdentityLookup::new(host("prometheus"))),
        CriomeRequest::AttestArchive(ArchiveAttestationRequest {
            component_release: ComponentRelease {
                principal_name: PrincipalName::new("persona-router"),
                object_digest: ObjectDigest::from_bytes(b"closure"),
                identity: developer("operator"),
            },
            audit_context: audit(ContentPurpose::Archive),
        }),
        CriomeRequest::AttestChannelGrant(ChannelGrantAttestationRequest {
            content_reference: content(ContentPurpose::ChannelGrant),
            identity: persona("mind"),
            audit_context: audit(ContentPurpose::ChannelGrant),
        }),
        CriomeRequest::AttestAuthorization(signal_criome::AuthorizationAttestationRequest {
            content_reference: content(ContentPurpose::Authorization),
            identity: persona("mind"),
            audit_context: audit(ContentPurpose::Authorization),
        }),
        CriomeRequest::AuthorizeSignalCall(signal_call_authorization()),
        CriomeRequest::ObserveAuthorization(AuthorizationObservation::new(
            authorization_request_slot(),
        )),
        CriomeRequest::ObserveParkedAuthorizations(ParkedAuthorizationObservation::new()),
        CriomeRequest::VerifyAuthorization(AuthorizationVerification {
            object_digest: ObjectDigest::from_bytes(b"signal-lojix request"),
            authorization_grant: authorization_grant(),
        }),
        CriomeRequest::RouteSignatureRequest(SignatureSolicitationRoute {
            signature_solicitation: signature_solicitation(),
            identity: host("balboa"),
        }),
        CriomeRequest::SubmitSignature(SignatureSubmission {
            authorization_request_slot: authorization_request_slot(),
            identity: developer("reviewer"),
            stamped_signature_envelope: stamped_envelope(),
        }),
        CriomeRequest::RejectAuthorization(AuthorizationRejection {
            authorization_request_slot: authorization_request_slot(),
            identity: developer("reviewer"),
            authorization_denial_reason: AuthorizationDenialReason::SignatureRejected,
        }),
        CriomeRequest::AdmitContract(policy_contract()),
        CriomeRequest::LookupContract(contract_digest()),
        CriomeRequest::EvaluateAuthorization(authorization_evaluation()),
        CriomeRequest::ObserveAuthorizedObjects(AuthorizedObjectObservation {
            identity: agent("operator"),
            authorized_object_interest: AuthorizedObjectInterest::Component(ComponentKind::Spirit),
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
        principal_status: PrincipalStatus::Active,
    };
    let replies = vec![
        CriomeReply::Signed(SignReceipt {
            attestation: attestation(ContentPurpose::SignedObject),
            timestamp_nanos: TimestampNanos::new(1),
        }),
        CriomeReply::Verified(VerificationResult::new(
            VerificationDecision::Valid,
            Some(developer("operator")),
            Some(TimestampNanos::new(2)),
        )),
        CriomeReply::IdentityRegistered(receipt.clone()),
        CriomeReply::Identities(IdentitySnapshot::from_identities(vec![receipt.clone()])),
        CriomeReply::Attested(AttestationReceipt::new(attestation(
            ContentPurpose::Archive,
        ))),
        CriomeReply::Pending(AuthorizationPending::new(
            authorization_request_slot(),
            ObjectDigest::from_bytes(b"signal-lojix request"),
            vec![developer("reviewer")],
            authorization_observation_token(),
        )),
        CriomeReply::AuthorizationGranted(authorization_grant()),
        CriomeReply::Denied(AuthorizationDenied {
            authorization_request_slot: authorization_request_slot(),
            authorization_denial: AuthorizationDenial {
                authorization_denial_source: AuthorizationDenialSource::Policy,
                authorization_denial_reason: AuthorizationDenialReason::SignatureScopeMismatch,
            },
        }),
        CriomeReply::Expired(AuthorizationExpired {
            authorization_request_slot: authorization_request_slot(),
            timestamp_nanos: TimestampNanos::new(13),
        }),
        CriomeReply::Unavailable(AuthorizationUnavailable {
            authorization_request_slot: authorization_request_slot(),
            principal_name: PrincipalName::new("criome-peer-unreachable"),
        }),
        CriomeReply::AuthorizationObserved(AuthorizationObservationSnapshot::from_states(vec![
            authorization_state(AuthorizationStatus::Pending),
        ])),
        CriomeReply::ParkedAuthorizations(ParkedAuthorizationSnapshot::from_parked(vec![
            ParkedAuthorization::from_evaluation(
                authorization_request_slot(),
                authorization_evaluation(),
            ),
        ])),
        CriomeReply::SignatureRouted(SignatureRouteReceipt {
            authorization_request_slot: authorization_request_slot(),
            identity: host("balboa"),
        }),
        CriomeReply::SignatureSubmitted(SignatureSubmissionReceipt {
            authorization_request_slot: authorization_request_slot(),
            identity: developer("reviewer"),
        }),
        CriomeReply::ContractAccepted(ContractAdmitted::new(contract_digest())),
        CriomeReply::ContractLocated(ContractFound {
            contract_digest: contract_digest(),
            contract: policy_contract(),
        }),
        CriomeReply::ContractAbsent(ContractMissing::new(contract_digest())),
        CriomeReply::ContractRefused(ContractAdmissionRejected::new(
            ContractAdmissionRejectionReason::DuplicatePolicyMember,
        )),
        CriomeReply::AuthorizationJudged(AuthorizationEvaluated {
            contract_digest: contract_digest(),
            evaluation_decision: EvaluationDecision::Rejected(
                EvaluationRejectionReason::QuorumShort(QuorumShortfall {
                    required: RequiredSignatureThreshold::new(2),
                    satisfied: RequiredSignatureThreshold::new(1),
                }),
            ),
        }),
        CriomeReply::AuthorizedObjectsUpdated(AuthorizedObjectUpdateSnapshot::from_updates(vec![
            authorized_object_update(),
        ])),
        CriomeReply::AuthorizedObjectRetracted(AuthorizedObjectUpdateRetracted::new(
            authorized_object_update_token(),
        )),
        CriomeReply::AuthorizationObservationClosed(AuthorizationObservationRetracted::new(
            authorization_observation_token(),
        )),
        CriomeReply::SubscriptionClosed(SubscriptionRetracted::new(
            IdentitySubscriptionToken::new(agent("operator")),
        )),
        CriomeReply::Refused(Rejection::new(RejectionReason::ReplayAttempted)),
        CriomeReply::QuorumRoundOpened(quorum_round_state()),
        CriomeReply::QuorumVoteSolicited(quorum_round_state()),
        CriomeReply::QuorumVoteAccepted(quorum_round_state()),
        CriomeReply::QuorumRoundObserved(quorum_round_state()),
        CriomeReply::PublicKeyObserved(node_public_key()),
        CriomeReply::QuorumRefused(quorum_conflict()),
        CriomeReply::FoundingConveyed(founding_conveyance_receipt()),
    ];

    for reply in replies {
        assert_eq!(round_trip_reply(reply.clone()), reply);
    }
}

#[test]
fn authorization_grant_carries_satisfied_policy_threshold() {
    let grant = authorization_grant();

    assert_eq!(
        grant.authorization_request_slot,
        authorization_request_slot()
    );
    assert_eq!(
        grant
            .authorization_policy_satisfaction
            .authorization_policy_class,
        AuthorizationPolicyClass::ComplexQuorum,
    );
    assert_eq!(
        grant
            .authorization_policy_satisfaction
            .required_signature_threshold
            .into_u16(),
        1,
    );
    assert_eq!(
        grant.authorization_policy_satisfaction.identity_vector(),
        &[cluster("uranus")],
    );
}

#[test]
fn quorum_signed_surfaces_carry_attested_moment_stamps() {
    let source = std::fs::read_to_string("schema/lib.schema").expect("read schema");

    for required in [
        "StampedSignatureEnvelope.{ AttestedMoment SignatureEnvelope }",
        "Vector.StampedSignatureEnvelope",
    ] {
        assert!(
            source.contains(required),
            "schema missing stamped signature surface: {required}"
        );
    }
    assert!(
        source.contains("TimeSignature.{ Identity SignatureEnvelope }"),
        "time signatures must stay bare because they create AttestedMoment"
    );
}

#[test]
fn authorized_object_update_carries_references_not_payloads() {
    let source = std::fs::read_to_string("schema/lib.schema").expect("read schema");

    assert!(
        source.contains(
            "AuthorizedObjectReference.{ ComponentKind ObjectDigest AuthorizedObjectKind }"
        )
    );
    assert!(source.contains(
        "AuthorizedObjectUpdate.{ AuthorizedObjectReference ContractDigest EvaluationDecision AttestedMoment }"
    ));
    assert!(
        !source.contains("AuthorizedObjectUpdate.{ Contract"),
        "authorized object pulse must not carry inline contract payloads"
    );
}

#[test]
fn authorization_denial_distinguishes_policy_from_signer_refusal() {
    let policy_denial = AuthorizationDenied {
        authorization_request_slot: authorization_request_slot(),
        authorization_denial: AuthorizationDenial {
            authorization_denial_source: AuthorizationDenialSource::Policy,
            authorization_denial_reason: AuthorizationDenialReason::PolicyRefused,
        },
    };
    let signer_denial = AuthorizationDenied {
        authorization_request_slot: authorization_request_slot(),
        authorization_denial: AuthorizationDenial {
            authorization_denial_source: AuthorizationDenialSource::Signers,
            authorization_denial_reason: AuthorizationDenialReason::SignerThresholdRejected,
        },
    };

    assert_ne!(policy_denial, signer_denial);
    assert_eq!(
        round_trip_reply(CriomeReply::Denied(policy_denial.clone())),
        CriomeReply::Denied(policy_denial)
    );
    assert_eq!(
        round_trip_reply(CriomeReply::Denied(signer_denial.clone())),
        CriomeReply::Denied(signer_denial)
    );
}

#[test]
fn intercept_policy_and_parked_spirit_request_model_round_trips() {
    let proposal = InterceptPolicyProposal {
        mentci_session_slot: mentci_session_slot(),
        intercept_target_selector: intercept_target(),
        spirit_operation_names: spirit_operation_names(),
        policy_duration_nanos: PolicyDurationNanos::new(100),
        expiry_action: ExpiryAction::AutoApprove,
        policy_priority: PolicyPriority::new(50),
        policy_overlap_mode: PolicyOverlapMode::RejectSamePriorityOverlap,
    };
    let policies = ActiveInterceptPolicies::from_policies(vec![intercept_policy()]);
    let parked_requests = ParkedRequestSnapshot::from_requests(vec![parked_spirit_request()]);
    let manual_rejection = ParkedRequestResolution {
        parked_request_identifier: ParkedRequestIdentifier::new("parked-request-1"),
        intercept_policy_identifier: intercept_policy_identifier(),
        parked_request_outcome: ParkedRequestOutcome::Rejected,
        approval_audit_source: ApprovalAuditSource::Manual,
        timestamp_nanos: TimestampNanos::new(130),
    };
    let automatic_approval = ParkedRequestResolution {
        parked_request_identifier: ParkedRequestIdentifier::new("parked-request-1"),
        intercept_policy_identifier: intercept_policy_identifier(),
        parked_request_outcome: ParkedRequestOutcome::Approved,
        approval_audit_source: ApprovalAuditSource::Automatic,
        timestamp_nanos: TimestampNanos::new(200),
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
        workflow_digest: workflow_digest(),
        identity: agent("guardian-runner"),
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
    let contract = Contract::root(Rule::composite(composition.clone()));

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
        let reply = CriomeReply::AuthorizationJudged(AuthorizationEvaluated {
            contract_digest: contract_digest(),
            evaluation_decision: decision,
        });
        assert_eq!(round_trip_reply(reply.clone()), reply);
    }
}

#[test]
fn workflow_receipts_and_peer_cosignatures_ride_evidence() {
    let evidence = evidence()
        .with_workflow_receipts(vec![workflow_receipt()])
        .with_object_co_signatures(vec![object_co_signature()]);

    assert_eq!(evidence.workflow_receipt_vector(), &[workflow_receipt()]);
    assert_eq!(
        evidence.object_co_signature_vector(),
        &[object_co_signature()]
    );

    let evaluation = AuthorizationEvaluation {
        contract_digest: contract_digest(),
        authorized_object_reference: authorized_object_reference(),
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

/// `RouterSubmissionConfiguration` selects criome's router submission path on
/// `CriomeDaemonConfiguration` (primary-79z1.21, Slice C). Absent, the daemon
/// stays on `NoConveyance`; present, `from_configuration` reads exactly this
/// record back out. Proves the accessor-projected route table and the whole
/// configuration round-trip through NOTA text unchanged.
#[test]
fn router_submission_configuration_selects_the_daemon_router_path() {
    let route = PeerActorRoute::new(host("node-b"), ActorIdentifier::new("criome-b-inbox"));
    let router_submission = RouterSubmissionConfiguration::new(
        "/run/criome/router.sock",
        ActorIdentifier::new("criome-a-outbox"),
        vec![route.clone()],
    );

    assert_eq!(
        router_submission.daemon_path(),
        &DaemonPath::new("/run/criome/router.sock")
    );
    assert_eq!(router_submission.peer_actor_route_vector(), &[route]);

    let configuration =
        CriomeDaemonConfiguration::new("/run/criome/criome.sock", "/var/lib/criome")
            .with_router_submission(router_submission.clone());
    assert_eq!(
        configuration.optional_router_submission_configuration(),
        Some(&router_submission)
    );

    assert_nota_round_trip(configuration);
}

/// The cluster-authorization surfaces of the 0.9 line: a quorum-granted
/// `AuthorizationStateRecord` carries its `granted_evidence` hand-off (the
/// operational contract digest, the authorized object, and the assembled
/// quorum Evidence a receiving node later re-judges), and the daemon
/// configuration carries the owner-configured `quorum_window`. Both survive
/// the wire unchanged.
#[test]
fn cluster_authorization_surfaces_round_trip() {
    let granted = authorization_state(AuthorizationStatus::Granted)
        .with_granted_evidence(authorization_evaluation());
    assert_eq!(
        granted.granted_evidence(),
        Some(&authorization_evaluation())
    );
    assert_nota_round_trip(granted);

    let quorum_window = QuorumWindowNanos::new(8_000_000_000);
    let configuration =
        CriomeDaemonConfiguration::new("/run/criome/criome.sock", "/var/lib/criome")
            .with_quorum_window(quorum_window.clone());
    assert_eq!(
        configuration.optional_quorum_window_nanos(),
        Some(&quorum_window)
    );
    assert_nota_round_trip(configuration);
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
        CriomeReply::Verified(VerificationResult::new(
            VerificationDecision::UnknownSigner,
            None,
            None,
        )),
        "(Verified (UnknownSigner None None))",
    );
}

#[test]
fn parent_link_and_root_founding_surfaces_round_trip() {
    // The parent link re-digests the contract: a Root sentinel and a child from
    // the same rule are different content addresses, and both survive the wire.
    let root = Contract::root(Rule::EscalateToPsyche);
    let child = Contract::child(Rule::EscalateToPsyche, contract_digest());
    assert_eq!(root.contract_parent(), &ContractParent::Root);
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
    assert_eq!(genesis.founding_member_vector().len(), 2);
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
