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

impl CriomeDaemonConfiguration {
    pub fn new(socket_path: impl Into<String>, store_path: impl Into<String>) -> Self {
        Self {
            socket_path: DaemonPath::new(socket_path.into()),
            store_path: DaemonPath::new(store_path.into()),
            meta_socket_path: None,
            cluster_root: None,
            authorization_mode: AuthorizationMode::Quorum,
            node_identity: None,
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
        request_digest: ObjectDigest,
        contract: ContractName,
        operation: ContractOperationHead,
        scope: AuthorizationScope,
        requester: Identity,
        nonce: ReplayNonce,
        expires_at: Option<TimestampNanos>,
    ) -> Self {
        Self {
            request_digest,
            contract,
            operation,
            scope,
            requester,
            nonce,
            signal_call_expires_at: expires_at,
            spirit_context: None,
        }
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
        authorized_object_digest: ObjectDigest,
        authorized_contract: ContractName,
        authorized_operation: ContractOperationHead,
        authorization_scope: AuthorizationScope,
        policy_satisfaction: AuthorizationPolicySatisfaction,
        signature_result: SignatureAuthorizationResult,
        signatures: Vec<StampedSignatureEnvelope>,
        issued_by: Identity,
        issued_at: TimestampNanos,
        expires_at: Option<TimestampNanos>,
    ) -> Self {
        Self {
            request_slot,
            authorized_object_digest,
            authorized_contract,
            authorized_operation,
            authorization_scope,
            policy_satisfaction,
            signature_result,
            authorization_grant_signatures: signatures,
            issued_by,
            issued_at,
            authorization_grant_expires_at: expires_at,
        }
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
