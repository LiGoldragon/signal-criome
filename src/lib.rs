//! Schema-derived Signal contract for Criome trust and attestation records.
//!
//! Wire-only vocabulary emitted from `schema/lib.schema`. This module adds the
//! hand-written escape-hatch methods over the emitted types (string accessors,
//! digest hashing, integer projections, and the daemon-configuration rkyv
//! helpers) plus the criome-named channel type aliases.

#[rustfmt::skip]
#[allow(clippy::large_enum_variant, dead_code, private_interfaces)]
pub mod schema;

pub use schema::lib::*;

/// Criome-named aliases over the emitted channel roots.
pub type CriomeRequest = Input;
pub type CriomeReply = Output;
pub type CriomeFrame = signal_frame::StreamingFrame<Input, Output, CriomeEvent>;
pub type CriomeFrameBody = signal_frame::StreamingFrameBody<Input, Output, CriomeEvent>;
pub type CriomeReplyEnvelope = ReplyEnvelope;
pub type CriomeRequestBuilder = RequestBuilder;
pub type CriomeOperationKind = InputRoute;

impl Input {
    pub fn operation_kind(&self) -> InputRoute {
        self.route()
    }
}

macro_rules! string_accessor {
    ($($type:ident),* $(,)?) => {
        $(
            impl $type {
                pub fn as_str(&self) -> &str {
                    self.payload().as_str()
                }
            }
        )*
    };
}

string_accessor!(
    DaemonPath,
    ActorIdentifier,
    PrincipalName,
    PrincipalId,
    PublicKeyFingerprint,
    BlsPublicKey,
    BlsSignature,
    ObjectDigest,
    ContractDigest,
    OperationDigest,
    CompositionDigest,
    WorkflowDigest,
    WorkflowProvenanceDigest,
    ReplayNonce,
    ContractName,
    AuthorizationRequestSlot,
    AuthorizationScope,
    ContractOperationHead,
    WorkflowStepName,
    InterceptPolicyIdentifier,
    MentciSessionSlot,
    SpiritProcessKey,
    SpiritOperationName,
    RawSpiritOperationPayload,
    ParkedRequestIdentifier,
    QuorumRoundIdentifier,
    RootAnchorDigest,
);

impl ObjectDigest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(blake3::hash(bytes).to_hex().to_string())
    }
}

impl ContractDigest {
    pub fn from_contract(contract: &Contract) -> Result<Self, ContractDigestError> {
        contract.digest()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(ObjectDigest::from_bytes(bytes))
    }

    pub fn object_digest(&self) -> &ObjectDigest {
        self.payload()
    }
}

impl OperationDigest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(ObjectDigest::from_bytes(bytes))
    }

    pub fn object_digest(&self) -> &ObjectDigest {
        self.payload()
    }
}

impl QuorumRoundIdentifier {
    /// Bind a quorum round to the fingerprint of the change it authorizes — the
    /// content-addressed operation (object) digest — AND to the round phase, so
    /// round 1 (Request) and round 2 (Commit) over the SAME object occupy
    /// distinct durable rounds and their signatures are never interchangeable.
    /// Deriving the round identifier from the operation digest makes a round-id
    /// collision across two distinct operations impossible by construction, so a
    /// second proposal can never clobber an unrelated in-flight round (the
    /// liveness lever the security audit flagged). The originator and each peer
    /// derive the SAME identifier from the SAME object and phase, and the criome
    /// ingress enforces the binding, so the round key carries no free-form caller
    /// choice.
    pub fn for_phase(operation: &ObjectDigest, phase: RoundPhase) -> Self {
        Self::new(format!(
            "quorum-round-{}-{}",
            phase.as_str(),
            operation.as_str()
        ))
    }

    /// The round-1 (Request phase) key for `operation`. Convenience over
    /// `for_phase(operation, RoundPhase::Request)` for the gather round and the
    /// single-gather fallback path.
    pub fn for_operation(operation: &ObjectDigest) -> Self {
        Self::for_phase(operation, RoundPhase::Request)
    }
}

impl RoundPhase {
    /// The canonical phase token woven into the phase-aware round key. Stable
    /// wire text — both peers derive the same round identifier from it.
    pub fn as_str(&self) -> &'static str {
        match self {
            RoundPhase::Request => "request",
            RoundPhase::Commit => "commit",
        }
    }
}

impl CompositionDigest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(ObjectDigest::from_bytes(bytes))
    }

    pub fn object_digest(&self) -> &ObjectDigest {
        self.payload()
    }
}

impl WorkflowDigest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(ObjectDigest::from_bytes(bytes))
    }

    pub fn object_digest(&self) -> &ObjectDigest {
        self.payload()
    }
}

impl WorkflowProvenanceDigest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(ObjectDigest::from_bytes(bytes))
    }

    pub fn object_digest(&self) -> &ObjectDigest {
        self.payload()
    }
}

impl AttestedMomentDigest {
    pub fn from_proposition(
        proposition: &AttestedMomentProposition,
    ) -> Result<Self, AttestedMomentDigestError> {
        proposition.digest()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(ObjectDigest::from_bytes(bytes))
    }

    pub fn object_digest(&self) -> &ObjectDigest {
        self.payload()
    }
}

impl Contract {
    /// Build a Criome unit from its policy rule and its parent link. The
    /// parent is provenance/authority derivation only — `Threshold::decide`
    /// evaluation does not read it — so a fresh contract must still name
    /// where it descends from: `ContractParent::Root` for a founded root,
    /// `ContractParent::Parent(digest)` for a child.
    pub fn new(rule: Rule, parent: ContractParent) -> Self {
        Self { rule, parent }
    }

    /// A root Criome unit: its own origin, no parent. `Root` is a
    /// distinguished sentinel, not a self-reference, so the digest never
    /// depends on a digest of itself.
    pub fn root(rule: Rule) -> Self {
        Self::new(rule, ContractParent::Root)
    }

    /// A child Criome unit whose authority derives from `parent`.
    pub fn child(rule: Rule, parent: ContractDigest) -> Self {
        Self::new(rule, ContractParent::Parent(parent))
    }

    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    pub fn parent(&self) -> &ContractParent {
        &self.parent
    }

    pub fn digest(&self) -> Result<ContractDigest, ContractDigestError> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|bytes| ContractDigest::from_bytes(bytes.as_ref()))
            .map_err(|_| ContractDigestError::Encode)
    }
}

impl AttestedMomentProposition {
    pub fn digest(&self) -> Result<AttestedMomentDigest, AttestedMomentDigestError> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|bytes| AttestedMomentDigest::from_bytes(bytes.as_ref()))
            .map_err(|_| AttestedMomentDigestError::Encode)
    }
}

impl Copy for TimestampNanos {}
impl Copy for PolicyDurationNanos {}
impl Copy for PolicyPriority {}
impl Copy for RequiredSignatureThreshold {}

impl TimestampNanos {
    pub fn into_u64(self) -> u64 {
        self.into_payload()
    }
}

impl PolicyDurationNanos {
    pub fn into_u64(self) -> u64 {
        self.into_payload()
    }
}

impl PolicyPriority {
    pub fn into_u64(self) -> u64 {
        self.into_payload()
    }
}

impl SpiritOperationNames {
    pub fn from_names(names: Vec<SpiritOperationName>) -> Self {
        Self::new(names)
    }

    pub fn names(&self) -> &[SpiritOperationName] {
        self.payload().as_slice()
    }

    pub fn into_names(self) -> Vec<SpiritOperationName> {
        self.into_payload()
    }
}

impl ActiveInterceptPolicies {
    pub fn from_policies(policies: Vec<InterceptPolicy>) -> Self {
        Self::new(InterceptPolicies::new(policies))
    }

    pub fn policies(&self) -> &[InterceptPolicy] {
        self.payload().payload().as_slice()
    }

    pub fn into_policies(self) -> Vec<InterceptPolicy> {
        self.into_payload().into_payload()
    }
}

impl ParkedRequestSnapshot {
    pub fn from_requests(requests: Vec<ParkedSpiritRequest>) -> Self {
        Self::new(ParkedSpiritRequests::new(requests))
    }

    pub fn requests(&self) -> &[ParkedSpiritRequest] {
        self.payload().payload().as_slice()
    }

    pub fn into_requests(self) -> Vec<ParkedSpiritRequest> {
        self.into_payload().into_payload()
    }
}

impl RequiredSignatureThreshold {
    pub fn into_u16(self) -> u16 {
        self.into_payload() as u16
    }
}

impl PeerActorRoute {
    /// One peer member mapped to the router destination-actor its conveyance
    /// is addressed to.
    pub fn new(peer: Identity, destination: ActorIdentifier) -> Self {
        Self { peer, destination }
    }

    pub fn peer(&self) -> &Identity {
        &self.peer
    }

    pub fn destination(&self) -> &ActorIdentifier {
        &self.destination
    }
}

impl RouterSubmissionConfiguration {
    /// Configure criome's router submission path: the local router socket this
    /// daemon originates conveyance over, the source actor it originates as,
    /// and the peer-to-destination route table.
    pub fn new(
        router_socket_path: impl Into<String>,
        source_actor: ActorIdentifier,
        peer_routes: Vec<PeerActorRoute>,
    ) -> Self {
        Self {
            router_socket_path: DaemonPath::new(router_socket_path.into()),
            source_actor,
            peer_routes,
        }
    }

    pub fn router_socket_path(&self) -> &DaemonPath {
        &self.router_socket_path
    }

    pub fn source_actor(&self) -> &ActorIdentifier {
        &self.source_actor
    }

    pub fn peer_routes(&self) -> &[PeerActorRoute] {
        self.peer_routes.as_slice()
    }
}

impl CriomeDaemonConfiguration {
    pub fn new(socket_path: impl Into<String>, store_path: impl Into<String>) -> Self {
        Self {
            socket_path: DaemonPath::new(socket_path.into()),
            store_path: DaemonPath::new(store_path.into()),
            meta_socket_path: None,
            cluster_root: None,
            authorization_mode: AuthorizationMode::Quorum,
            node_identity: None,
            router_submission: None,
            quorum_window: None,
        }
    }

    /// Set the authorization verdict mode: `Quorum` (default; gathered BLS
    /// signatures must satisfy the contract) or `AutoApprove` (a configured
    /// acceptance policy that authorizes every well-formed request, for
    /// bootstrap and testing). Spirit `t00s`.
    pub fn with_authorization_mode(mut self, authorization_mode: AuthorizationMode) -> Self {
        self.authorization_mode = authorization_mode;
        self
    }

    pub fn authorization_mode(&self) -> &AuthorizationMode {
        &self.authorization_mode
    }

    /// Set the private meta socket used by local user-owned approval/configuration
    /// clients such as Mentci.
    pub fn with_meta_socket_path(mut self, meta_socket_path: impl Into<String>) -> Self {
        self.meta_socket_path = Some(DaemonPath::new(meta_socket_path.into()));
        self
    }

    pub fn meta_socket_path(&self) -> Option<&DaemonPath> {
        self.meta_socket_path.as_ref()
    }

    /// Set the cluster-root trust anchor (the public key whose signature admits
    /// keys into the registry). Absent by default for dev/virgin bootstrap.
    pub fn with_cluster_root(mut self, cluster_root: BlsPublicKey) -> Self {
        self.cluster_root = Some(cluster_root);
        self
    }

    pub fn cluster_root(&self) -> Option<&BlsPublicKey> {
        self.cluster_root.as_ref()
    }

    /// Set the identity this criome signs attestations as. Absent by default,
    /// in which case the daemon falls back to its historical `Host("criome")`
    /// identity. A multi-node cluster gives each node a distinct identity (for
    /// example `Host("node-a")`) so a peer criome that has registered this
    /// node's public key under that identity can verify its attestations, while
    /// an unregistered identity is refused fail-closed.
    pub fn with_node_identity(mut self, node_identity: Identity) -> Self {
        self.node_identity = Some(node_identity);
        self
    }

    pub fn node_identity(&self) -> Option<&Identity> {
        self.node_identity.as_ref()
    }

    /// Configure criome's router submission path. Absent by default, in which
    /// case the daemon stays on `NoConveyance` (single-node / unconfigured).
    /// Present, the daemon conveys peer requests over the configured router
    /// socket instead.
    pub fn with_router_submission(
        mut self,
        router_submission: RouterSubmissionConfiguration,
    ) -> Self {
        self.router_submission = Some(router_submission);
        self
    }

    pub fn router_submission(&self) -> Option<&RouterSubmissionConfiguration> {
        self.router_submission.as_ref()
    }

    /// Set the owner-configured cluster authorization window: how long one
    /// quorum authorization (both commit rounds plus the catch-up case) may
    /// take before it expires fail-closed. Absent, the daemon default applies.
    pub fn with_quorum_window(mut self, quorum_window: QuorumWindowNanos) -> Self {
        self.quorum_window = Some(quorum_window);
        self
    }

    pub fn quorum_window(&self) -> Option<&QuorumWindowNanos> {
        self.quorum_window.as_ref()
    }

    pub fn from_rkyv_bytes(bytes: &[u8]) -> Result<Self, CriomeDaemonConfigurationArchiveError> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(bytes)
            .map_err(|_| CriomeDaemonConfigurationArchiveError::Decode)
    }

    pub fn to_rkyv_bytes(&self) -> Result<Vec<u8>, CriomeDaemonConfigurationArchiveError> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|bytes| bytes.to_vec())
            .map_err(|_| CriomeDaemonConfigurationArchiveError::Encode)
    }
}

impl AuthorizationPolicySatisfaction {
    pub fn new(
        policy_class: AuthorizationPolicyClass,
        required_signature_threshold: RequiredSignatureThreshold,
        satisfied_signers: Vec<Identity>,
    ) -> Self {
        Self {
            policy_class,
            required_signature_threshold,
            satisfied_signers,
        }
    }

    pub fn satisfied_signers(&self) -> &[Identity] {
        self.satisfied_signers.as_slice()
    }
}

impl Threshold {
    pub fn new(
        required_signatures: RequiredSignatureThreshold,
        members: Vec<PolicyMember>,
    ) -> Self {
        Self {
            required_signatures,
            members,
        }
    }

    pub fn members(&self) -> &[PolicyMember] {
        self.members.as_slice()
    }
}

impl AttestedMomentProposition {
    pub fn new(
        window: TimeWindow,
        required_signatures: RequiredSignatureThreshold,
        authorities: Vec<Identity>,
    ) -> Self {
        Self {
            window,
            required_signatures,
            authorities,
        }
    }

    pub fn authorities(&self) -> &[Identity] {
        self.authorities.as_slice()
    }
}

impl AttestedMoment {
    pub fn new(
        proposition: AttestedMomentProposition,
        time_signatures: Vec<TimeSignature>,
    ) -> Self {
        Self {
            proposition,
            time_signatures,
        }
    }

    pub fn signatures(&self) -> &[TimeSignature] {
        self.time_signatures.as_slice()
    }
}

impl Evidence {
    pub fn new(
        component: ComponentKind,
        operation: OperationDigest,
        stamp: AttestedMoment,
        evidence_signatures: Vec<StampedSignatureEnvelope>,
        agreements: Vec<AgreementFact>,
    ) -> Self {
        Self {
            component,
            operation,
            stamp,
            evidence_signatures,
            agreements,
            workflow_receipts: Vec::new(),
            object_co_signatures: Vec::new(),
        }
    }

    pub fn with_workflow_receipts(mut self, workflow_receipts: Vec<WorkflowReceipt>) -> Self {
        self.workflow_receipts = workflow_receipts;
        self
    }

    pub fn with_object_co_signatures(
        mut self,
        object_co_signatures: Vec<ObjectCoSignature>,
    ) -> Self {
        self.object_co_signatures = object_co_signatures;
        self
    }

    pub fn signatures(&self) -> &[StampedSignatureEnvelope] {
        self.evidence_signatures.as_slice()
    }

    pub fn agreements(&self) -> &[AgreementFact] {
        self.agreements.as_slice()
    }

    pub fn workflow_receipts(&self) -> &[WorkflowReceipt] {
        self.workflow_receipts.as_slice()
    }

    pub fn object_co_signatures(&self) -> &[ObjectCoSignature] {
        self.object_co_signatures.as_slice()
    }
}

impl CoSignatureExpectation {
    pub fn new(
        object: AuthorizedObjectReference,
        expected_signers: Vec<Identity>,
        observed_signers: Vec<Identity>,
    ) -> Self {
        Self {
            object,
            expected_signers,
            observed_signers,
        }
    }

    pub fn expected_signers(&self) -> &[Identity] {
        self.expected_signers.as_slice()
    }

    pub fn observed_signers(&self) -> &[Identity] {
        self.observed_signers.as_slice()
    }
}

impl Attestation {
    pub fn new(
        content: ContentReference,
        signer: Identity,
        envelope: SignatureEnvelope,
        issued_at: TimestampNanos,
        expires_at: Option<TimestampNanos>,
        audit_context: AuditContext,
    ) -> Self {
        Self {
            content,
            signer,
            envelope,
            issued_at,
            attestation_expires_at: expires_at,
            audit_context,
        }
    }

    pub fn expires_at(&self) -> Option<TimestampNanos> {
        self.attestation_expires_at
    }
}

impl SignalCallAuthorization {
    pub fn new(
        object: AuthorizedObjectReference,
        requester: Identity,
        nonce: ReplayNonce,
        expires_at: Option<TimestampNanos>,
    ) -> Self {
        Self {
            object,
            requester,
            nonce,
            signal_call_expires_at: expires_at,
            spirit_context: None,
        }
    }

    /// The digest of the typed object this ask names — the request's binding
    /// fingerprint (formerly the standalone `request_digest` field).
    pub fn request_digest(&self) -> &ObjectDigest {
        &self.object.digest
    }

    pub fn expires_at(&self) -> Option<TimestampNanos> {
        self.signal_call_expires_at
    }

    pub fn with_spirit_context(mut self, context: SpiritAuthorizationContext) -> Self {
        self.spirit_context = Some(context);
        self
    }

    pub fn spirit_context(&self) -> Option<&SpiritAuthorizationContext> {
        self.spirit_context.as_ref()
    }
}

impl AuthorizationGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_slot: AuthorizationRequestSlot,
        authorized_object: AuthorizedObjectReference,
        policy_satisfaction: AuthorizationPolicySatisfaction,
        signature_result: SignatureAuthorizationResult,
        signatures: Vec<StampedSignatureEnvelope>,
        issued_by: Identity,
        issued_at: TimestampNanos,
        expires_at: Option<TimestampNanos>,
    ) -> Self {
        Self {
            request_slot,
            authorized_object,
            policy_satisfaction,
            signature_result,
            authorization_grant_signatures: signatures,
            issued_by,
            issued_at,
            authorization_grant_expires_at: expires_at,
        }
    }

    /// The digest of the typed object this grant authorizes (formerly the
    /// standalone `authorized_object_digest` field).
    pub fn authorized_object_digest(&self) -> &ObjectDigest {
        &self.authorized_object.digest
    }

    pub fn signatures(&self) -> &[StampedSignatureEnvelope] {
        self.authorization_grant_signatures.as_slice()
    }

    pub fn expires_at(&self) -> Option<TimestampNanos> {
        self.authorization_grant_expires_at
    }
}

impl AuthorizationPending {
    pub fn new(
        request_slot: AuthorizationRequestSlot,
        request_digest: ObjectDigest,
        missing_authorities: Vec<Identity>,
        observation_token: AuthorizationObservationToken,
    ) -> Self {
        Self {
            request_slot,
            request_digest,
            pending_missing_authorities: missing_authorities,
            observation_token,
        }
    }

    pub fn missing_authorities(&self) -> &[Identity] {
        self.pending_missing_authorities.as_slice()
    }
}

impl AuthorizationStateRecord {
    pub fn new(
        request_slot: AuthorizationRequestSlot,
        request_digest: ObjectDigest,
        status: AuthorizationStatus,
        missing_authorities: Vec<Identity>,
        grant: Option<AuthorizationGrant>,
        denial: Option<AuthorizationDenial>,
    ) -> Self {
        Self {
            request_slot,
            request_digest,
            status,
            state_missing_authorities: missing_authorities,
            grant,
            denial,
            parked_evaluation: None,
            signal_authorization: None,
            granted_evidence: None,
        }
    }

    pub fn with_parked_evaluation(mut self, evaluation: AuthorizationEvaluation) -> Self {
        self.parked_evaluation = Some(evaluation);
        self
    }

    pub fn with_signal_authorization(mut self, authorization: SignalCallAuthorization) -> Self {
        self.signal_authorization = Some(authorization);
        self
    }

    /// Attach the cluster-authorization hand-off: the operational contract,
    /// the authorized object, and the assembled quorum Evidence a receiving
    /// node later re-judges.
    pub fn with_granted_evidence(mut self, evidence: AuthorizationEvaluation) -> Self {
        self.granted_evidence = Some(evidence);
        self
    }

    pub fn granted_evidence(&self) -> Option<&AuthorizationEvaluation> {
        self.granted_evidence.as_ref()
    }

    pub fn missing_authorities(&self) -> &[Identity] {
        self.state_missing_authorities.as_slice()
    }

    pub fn grant(&self) -> Option<&AuthorizationGrant> {
        self.grant.as_ref()
    }

    pub fn denial(&self) -> Option<&AuthorizationDenial> {
        self.denial.as_ref()
    }

    pub fn parked_evaluation(&self) -> Option<&AuthorizationEvaluation> {
        self.parked_evaluation.as_ref()
    }

    pub fn signal_authorization(&self) -> Option<&SignalCallAuthorization> {
        self.signal_authorization.as_ref()
    }
}

impl ParkedAuthorizationObservation {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for ParkedAuthorizationObservation {
    fn default() -> Self {
        Self::new()
    }
}

impl ParkedAuthorization {
    pub fn from_evaluation(
        request_slot: AuthorizationRequestSlot,
        evaluation: AuthorizationEvaluation,
    ) -> Self {
        Self {
            request_slot,
            parked_authorization_evaluation: Some(evaluation),
            parked_signal_authorization: None,
        }
    }

    pub fn from_signal_authorization(
        request_slot: AuthorizationRequestSlot,
        authorization: SignalCallAuthorization,
    ) -> Self {
        Self {
            request_slot,
            parked_authorization_evaluation: None,
            parked_signal_authorization: Some(authorization),
        }
    }

    pub fn evaluation(&self) -> Option<&AuthorizationEvaluation> {
        self.parked_authorization_evaluation.as_ref()
    }

    pub fn signal_authorization(&self) -> Option<&SignalCallAuthorization> {
        self.parked_signal_authorization.as_ref()
    }
}

impl ParkedAuthorizationSnapshot {
    pub fn from_parked(parked: Vec<ParkedAuthorization>) -> Self {
        Self::new(parked)
    }

    pub fn parked(&self) -> &[ParkedAuthorization] {
        self.payload().as_slice()
    }

    pub fn into_parked(self) -> Vec<ParkedAuthorization> {
        self.into_payload()
    }
}

impl SignRequest {
    pub fn new(
        content: ContentReference,
        signer: Identity,
        audit_context: AuditContext,
        expires_at: Option<TimestampNanos>,
    ) -> Self {
        Self {
            content,
            signer,
            audit_context,
            sign_request_expires_at: expires_at,
        }
    }

    pub fn expires_at(&self) -> Option<TimestampNanos> {
        self.sign_request_expires_at
    }
}

impl IdentityRegistration {
    pub fn new(
        identity: Identity,
        public_key: BlsPublicKey,
        fingerprint: PublicKeyFingerprint,
        purpose: KeyPurpose,
        admission: Option<SignatureEnvelope>,
    ) -> Self {
        Self {
            identity,
            public_key,
            fingerprint,
            purpose,
            admission,
        }
    }

    pub fn admission(&self) -> Option<&SignatureEnvelope> {
        self.admission.as_ref()
    }
}

impl VerificationResult {
    pub fn new(
        decision: VerificationDecision,
        identity: Option<Identity>,
        expires_at: Option<TimestampNanos>,
    ) -> Self {
        Self {
            decision,
            verified_identity: identity,
            verification_expires_at: expires_at,
        }
    }
}

impl IdentitySnapshot {
    pub fn from_identities(identities: Vec<IdentityReceipt>) -> Self {
        Self::new(identities)
    }

    pub fn identities(&self) -> &[IdentityReceipt] {
        self.payload().as_slice()
    }

    pub fn into_identities(self) -> Vec<IdentityReceipt> {
        self.into_payload()
    }
}

impl AuthorizationObservationSnapshot {
    pub fn from_states(states: Vec<AuthorizationStateRecord>) -> Self {
        Self::new(states)
    }

    pub fn states(&self) -> &[AuthorizationStateRecord] {
        self.payload().as_slice()
    }

    pub fn into_states(self) -> Vec<AuthorizationStateRecord> {
        self.into_payload()
    }
}

impl AuthorizedObjectUpdateSnapshot {
    pub fn from_updates(updates: Vec<AuthorizedObjectUpdate>) -> Self {
        Self::new(updates)
    }

    pub fn updates(&self) -> &[AuthorizedObjectUpdate] {
        self.payload().as_slice()
    }

    pub fn into_updates(self) -> Vec<AuthorizedObjectUpdate> {
        self.into_payload()
    }
}

impl DueContractChecksEvaluated {
    pub fn from_triggered(triggered: Vec<AuthorizedObjectUpdate>) -> Self {
        Self::new(triggered)
    }

    pub fn triggered(&self) -> &[AuthorizedObjectUpdate] {
        self.payload().as_slice()
    }

    pub fn into_triggered(self) -> Vec<AuthorizedObjectUpdate> {
        self.into_payload()
    }
}

impl RootAnchorDigest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(ObjectDigest::from_bytes(bytes))
    }

    pub fn object_digest(&self) -> &ObjectDigest {
        self.payload()
    }
}

impl GenesisDomainTag {
    /// The canonical domain-separation label the founding path is tagged with.
    /// Kept in the shared contract so signer and verifier agree byte-for-byte;
    /// a future scheme/curve split adds a variant rather than rewriting this.
    pub fn domain_separator(&self) -> &'static str {
        match self {
            GenesisDomainTag::CriomeRootFoundingV1 => "CRIOME-ROOT-FOUNDING-V1",
        }
    }
}

impl FoundingMember {
    pub fn new(identity: Identity, public_key: BlsPublicKey) -> Self {
        Self {
            identity,
            public_key,
        }
    }
}

impl RootGenesis {
    pub fn new(
        root_contract: Contract,
        founding_keys: Vec<FoundingMember>,
        domain: GenesisDomainTag,
        genesis_nonce: ReplayNonce,
    ) -> Self {
        Self {
            root_contract,
            founding_keys,
            domain,
            genesis_nonce,
        }
    }

    pub fn founding_keys(&self) -> &[FoundingMember] {
        self.founding_keys.as_slice()
    }

    /// The anchor every node bakes in: `blake3(rkyv(RootGenesis))`. Because the
    /// ordered `founding_keys` are embedded, the anchor COMMITS to the founding
    /// quorum's public keys — the self-certifying identity. Identity therefore
    /// exists the instant the genesis is built; founding only accumulates the
    /// attached signatures over it, it does not create identity.
    pub fn anchor(&self) -> Result<RootAnchorDigest, RootFoundingDigestError> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|bytes| RootAnchorDigest::from_bytes(bytes.as_ref()))
            .map_err(|_| RootFoundingDigestError::Encode)
    }
}

impl FoundingSignature {
    pub fn new(signer: Identity, envelope: SignatureEnvelope) -> Self {
        Self { signer, envelope }
    }
}

impl RootFoundingStatement {
    pub fn new(anchor: RootAnchorDigest, domain: GenesisDomainTag) -> Self {
        Self { anchor, domain }
    }

    /// The canonical preimage digest each founder's master key signs:
    /// `blake3(rkyv(RootFoundingStatement))`. The statement carries the anchor
    /// and the domain tag, so the signature is domain-separated and bound to the
    /// exact cohort. Signatures ride ATTACHED to the anchor — this digest is
    /// never folded back into the anchor hash.
    pub fn preimage_digest(&self) -> Result<ObjectDigest, RootFoundingDigestError> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|bytes| ObjectDigest::from_bytes(bytes.as_ref()))
            .map_err(|_| RootFoundingDigestError::Encode)
    }
}

impl NodePublicKey {
    pub fn public_key(&self) -> &BlsPublicKey {
        self.payload()
    }
}

impl NodePublicKeyObservation {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for NodePublicKeyObservation {
    fn default() -> Self {
        Self::new()
    }
}

impl QuorumConflict {
    /// The typed "refused, resubmit" reply: this node already co-signed
    /// `existing_successor` from `at_head` on `contract`, so a different
    /// successor from the same head is refused (one honest successor per
    /// state-point).
    pub fn new(
        contract: ContractDigest,
        at_head: ContractOperationHead,
        existing_successor: AuthorizedObjectReference,
    ) -> Self {
        Self {
            contract,
            at_head,
            existing_successor,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RootFoundingDigestError {
    #[error("failed to encode criome root-founding record before digesting it")]
    Encode,
}

#[derive(Debug, thiserror::Error)]
pub enum CriomeDaemonConfigurationArchiveError {
    #[error("failed to encode criome daemon configuration archive")]
    Encode,

    #[error("failed to decode criome daemon configuration archive")]
    Decode,
}

#[derive(Debug, thiserror::Error)]
pub enum ContractDigestError {
    #[error("failed to encode criome contract before digesting it")]
    Encode,
}

#[derive(Debug, thiserror::Error)]
pub enum AttestedMomentDigestError {
    #[error("failed to encode criome attested moment proposition before digesting it")]
    Encode,
}
