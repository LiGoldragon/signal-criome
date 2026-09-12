#![allow(dead_code, non_camel_case_types, non_snake_case)]
#[rustfmt::skip]
pub type BlsPublicKey = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationAttestationRequest {
    pub content_reference: ContentReference,
    pub identity: Identity,
    pub audit_context: AuditContext,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ParkedRequestQuery {
    pub mentci_session_slot_option: Option<MentciSessionSlot>,
    pub intercept_target_selector_option: Option<InterceptTargetSelector>,
}
#[rustfmt::skip]
pub type RequiredSignatureThreshold = i64;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum EvaluationDecision {
    Escalate(EscalationTarget),
    Authorized,
    NonJudgement,
    Deferred,
    Rejected(EvaluationRejectionReason),
}
#[rustfmt::skip]
pub type ReplayNonce = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SpiritAuthorizationContext {
    pub spirit_operation_name: SpiritOperationName,
    pub raw_spirit_operation_payload: RawSpiritOperationPayload,
    pub spirit_process_key: SpiritProcessKey,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AttestedMomentProposition {
    pub time_window: TimeWindow,
    pub required_signature_threshold: RequiredSignatureThreshold,
    pub identity_vector: std::vec::Vec<Identity>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct FoundingSignatureReturn {
    pub root_anchor_digest: RootAnchorDigest,
    pub founding_signature: FoundingSignature,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct StampedSignatureEnvelope {
    pub attested_moment: AttestedMoment,
    pub signature_envelope: SignatureEnvelope,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizedObjectObservation {
    pub identity: Identity,
    pub authorized_object_interest: signal::AuthorizedObjectInterest,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AgreementRule {
    pub first_object_digest: signal::ObjectDigest,
    pub second_object_digest: signal::ObjectDigest,
    pub identity: Identity,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct TimeSignature {
    pub identity: Identity,
    pub signature_envelope: SignatureEnvelope,
}
#[rustfmt::skip]
pub type ParkedSpiritRequests = std::vec::Vec<ParkedSpiritRequest>;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AttestedMoment {
    pub attested_moment_proposition: AttestedMomentProposition,
    pub time_signature_vector: std::vec::Vec<TimeSignature>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizedObjectUpdate {
    pub authorized_object_reference: signal::AuthorizedObjectReference,
    pub contract_digest: ContractDigest,
    pub evaluation_decision: EvaluationDecision,
    pub attested_moment: AttestedMoment,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum VerificationDecision {
    InvalidSignature,
    UnknownSigner,
    ReplayAttempted,
    Valid,
    Revoked,
    Expired,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SignatureEnvelope {
    pub signature_scheme: SignatureScheme,
    pub bls_public_key: BlsPublicKey,
    pub bls_signature: BlsSignature,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum PolicyOverlapMode {
    ReplaceSamePriorityOverlap,
    RejectSamePriorityOverlap,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct WorkflowGuard {
    pub workflow_digest: WorkflowDigest,
    pub identity: Identity,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct QuorumConflict {
    pub contract_digest: ContractDigest,
    pub contract_operation_head: ContractOperationHead,
    pub authorized_object_reference: signal::AuthorizedObjectReference,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationUpdate {
    pub authorization_state_record: AuthorizationStateRecord,
}
#[rustfmt::skip]
pub type BlsSignature = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct VerifyRequest {
    pub attestation: Attestation,
    pub content_reference: ContentReference,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ParkedAuthorization {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub authorization_evaluation_option: Option<AuthorizationEvaluation>,
    pub signal_call_authorization_option: Option<SignalCallAuthorization>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizedObjectUpdateToken {
    pub identity: Identity,
    pub authorized_object_interest: signal::AuthorizedObjectInterest,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct IdentityRevocation {
    pub identity: Identity,
    pub public_key_fingerprint: PublicKeyFingerprint,
    pub principal_name: PrincipalName,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct FoundedRoot {
    pub root_genesis: RootGenesis,
    pub founding_signature_vector: std::vec::Vec<FoundingSignature>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct IdentitySubscription {
    pub identity: Identity,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationPending {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub object_digest: signal::ObjectDigest,
    pub identity_vector: std::vec::Vec<Identity>,
    pub authorization_observation_token: AuthorizationObservationToken,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum FoundingConveyance {
    Signature(FoundingSignatureReturn),
    Founded(FoundedRoot),
    Proposal(FoundingProposal),
}
#[rustfmt::skip]
pub type AuthorizationRequestSlot = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationDenied {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub authorization_denial: AuthorizationDenial,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct FoundingMember {
    pub identity: Identity,
    pub bls_public_key: BlsPublicKey,
}
#[rustfmt::skip]
pub type AttestedMomentDigest = signal::ObjectDigest;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ActiveInterceptPolicies {
    pub intercept_policies: InterceptPolicies,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum EscalationTarget {
    SmarterAgent(Identity),
    Psyche,
    Workflow(WorkflowDigest),
}
#[rustfmt::skip]
pub type WorkflowStepName = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationRejection {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub identity: Identity,
    pub authorization_denial_reason: AuthorizationDenialReason,
}
#[rustfmt::skip]
pub type OperationDigest = signal::ObjectDigest;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuditContext {
    pub content_purpose: ContentPurpose,
    pub first_principal_name: PrincipalName,
    pub second_principal_name: PrincipalName,
    pub replay_nonce: ReplayNonce,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SignedPersonaRequest {
    pub identity: Identity,
    pub content_reference: ContentReference,
    pub delegation_grant_option: Option<DelegationGrant>,
    pub signature_envelope: SignatureEnvelope,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum FoundingConveyanceOutcome {
    RootFounded,
    ProposalPending,
    SignatureAccumulated,
    Refused,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct Evidence {
    pub component_kind: signal::ComponentKind,
    pub operation_digest: OperationDigest,
    pub attested_moment: AttestedMoment,
    pub stamped_signature_envelope_vector: std::vec::Vec<StampedSignatureEnvelope>,
    pub agreement_fact_vector: std::vec::Vec<AgreementFact>,
    pub workflow_receipt_vector: std::vec::Vec<WorkflowReceipt>,
    pub object_co_signature_vector: std::vec::Vec<ObjectCoSignature>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct QuorumRoundQuery {
    pub quorum_round_identifier: QuorumRoundIdentifier,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum EvaluationRejectionReason {
    SignatureMissing(Identity),
    AgreementMissing,
    QuorumShort(QuorumShortfall),
    OutsideTimeWindow,
    TimeNotProven,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum Identity {
    Persona(PrincipalName),
    Host(PrincipalName),
    Developer(PrincipalName),
    Agent(PrincipalName),
    Cluster(PrincipalName),
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum Composition {
    Threshold(CompositionThreshold),
    AllOf(std::vec::Vec<CompositionDigest>),
    Escalate(EscalationTarget),
    AnyOf(std::vec::Vec<CompositionDigest>),
    WorkflowStep(WorkflowStepName),
    Signature(Identity),
}
#[rustfmt::skip]
pub type PrincipalId = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct FoundingProposal {
    pub root_genesis: RootGenesis,
    pub identity: Identity,
}
#[rustfmt::skip]
pub type QuorumRoundIdentifier = String;
#[rustfmt::skip]
pub type QuorumWindowNanos = i64;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SignatureRouteReceipt {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub identity: Identity,
}
#[rustfmt::skip]
pub type WorkflowDigest = signal::ObjectDigest;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationStateRecord {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub object_digest: signal::ObjectDigest,
    pub authorization_status: AuthorizationStatus,
    pub identity_vector: std::vec::Vec<Identity>,
    pub authorization_grant_option: Option<AuthorizationGrant>,
    pub authorization_denial_option: Option<AuthorizationDenial>,
    pub first_authorization_evaluation_option: Option<AuthorizationEvaluation>,
    pub signal_call_authorization_option: Option<SignalCallAuthorization>,
    pub second_authorization_evaluation_option: Option<AuthorizationEvaluation>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ContractTimeCheckScheduled {
    pub contract_time_check: ContractTimeCheck,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum AuthorizationStatus {
    Unavailable,
    Denied,
    Expired,
    Granted,
    Parked,
    Pending,
    Signing,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SignatureSubmission {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub identity: Identity,
    pub stamped_signature_envelope: StampedSignatureEnvelope,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationPolicySatisfaction {
    pub authorization_policy_class: AuthorizationPolicyClass,
    pub required_signature_threshold: RequiredSignatureThreshold,
    pub identity_vector: std::vec::Vec<Identity>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct QuorumVote {
    pub quorum_round_identifier: QuorumRoundIdentifier,
    pub round_phase: RoundPhase,
    pub identity: Identity,
    pub first_signature_envelope: SignatureEnvelope,
    pub second_signature_envelope: SignatureEnvelope,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum ApprovalAuditSource {
    Automatic,
    Manual,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct InterceptPolicy {
    pub intercept_policy_identifier: InterceptPolicyIdentifier,
    pub mentci_session_slot: MentciSessionSlot,
    pub intercept_target_selector: InterceptTargetSelector,
    pub spirit_operation_names: SpiritOperationNames,
    pub intercept_policy_window: InterceptPolicyWindow,
    pub expiry_action: ExpiryAction,
    pub policy_priority: PolicyPriority,
}
#[rustfmt::skip]
pub type SpiritOperationName = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct RouterSubmissionConfiguration {
    pub daemon_path: DaemonPath,
    pub actor_identifier: ActorIdentifier,
    pub peer_actor_route_vector: std::vec::Vec<PeerActorRoute>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum AuthorizationPolicyClass {
    SimpleSelfSigned,
    ComplexQuorum,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SignalCallAuthorization {
    pub authorized_object_reference: signal::AuthorizedObjectReference,
    pub identity: Identity,
    pub replay_nonce: ReplayNonce,
    pub timestamp_nanos_option: Option<TimestampNanos>,
    pub spirit_authorization_context_option: Option<SpiritAuthorizationContext>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct TimedRule {
    pub timestamp_nanos: TimestampNanos,
    pub identity: Identity,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationEvaluated {
    pub contract_digest: ContractDigest,
    pub evaluation_decision: EvaluationDecision,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ContractFound {
    pub contract_digest: ContractDigest,
    pub contract: Contract,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AttestationReceipt {
    pub attestation: Attestation,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SignReceipt {
    pub attestation: Attestation,
    pub timestamp_nanos: TimestampNanos,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ComponentReleaseRecord {
    pub principal_name: PrincipalName,
    pub object_digest: signal::ObjectDigest,
    pub identity: Identity,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationUnavailable {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub principal_name: PrincipalName,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct RootGenesis {
    pub contract: Contract,
    pub founding_member_vector: std::vec::Vec<FoundingMember>,
    pub genesis_domain_tag: GenesisDomainTag,
    pub replay_nonce: ReplayNonce,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct IdentityLookup {
    pub identity: Identity,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationObservation {
    pub authorization_request_slot: AuthorizationRequestSlot,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct InterceptPolicyWindow {
    pub first_timestamp_nanos: TimestampNanos,
    pub second_timestamp_nanos: TimestampNanos,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum ContractAdmissionRejectionReason {
    EmptyThreshold,
    DuplicatePolicyMember,
    DanglingReference(ContractDigest),
    EmptyConjunction,
    ThresholdUnsatisfiable,
    EmptyDisjunction,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationVerification {
    pub object_digest: signal::ObjectDigest,
    pub authorization_grant: AuthorizationGrant,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SignRequest {
    pub content_reference: ContentReference,
    pub identity: Identity,
    pub audit_context: AuditContext,
    pub timestamp_nanos_option: Option<TimestampNanos>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum KeyPurpose {
    CriomeRoot,
    HostPublication,
    ReleaseAuthorization,
    PersonaRequest,
    AgentRequest,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum ExpiryAction {
    LeaveParked,
    AutoReject,
    AutoApprove,
}
#[rustfmt::skip]
pub type WorkflowProvenanceDigest = signal::ObjectDigest;
#[rustfmt::skip]
pub type CompositionThreshold = i64;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum ParkedRequestDecision {
    Approve,
    Reject,
}
#[rustfmt::skip]
pub type ParkedRequestIdentifier = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct WorkflowReceipt {
    pub workflow_digest: WorkflowDigest,
    pub operation_digest: OperationDigest,
    pub evaluation_decision: EvaluationDecision,
    pub workflow_provenance_digest: WorkflowProvenanceDigest,
}
#[rustfmt::skip]
pub type SpiritOperationNames = std::vec::Vec<SpiritOperationName>;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum AuthorizationMode {
    AutoApprove,
    ClientApproval,
    Quorum,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct RootFoundingStatement {
    pub root_anchor_digest: RootAnchorDigest,
    pub genesis_domain_tag: GenesisDomainTag,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SubscriptionRetracted {
    pub identity_subscription_token: IdentitySubscriptionToken,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum RejectionReason {
    ReplayAttempted,
    UnauthorizedRegistration,
    OutsideTimeWindow,
    StaleVote,
    UnknownIdentity,
    ForgedVote,
    SelfLoopSuccessor,
    MalformedRequest,
    UnsupportedSignatureScheme,
    DuplicateIdentity,
    RevokedIdentity,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct QuorumProposal {
    pub quorum_round_identifier: QuorumRoundIdentifier,
    pub round_phase: RoundPhase,
    pub contract_digest: ContractDigest,
    pub authorized_object_reference: signal::AuthorizedObjectReference,
    pub time_window: TimeWindow,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum SignatureScheme {
    Bls12_381MinSig,
    Bls12_381MinPk,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum PrincipalStatus {
    Revoked,
    Active,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum ParkedRequestOutcome {
    Rejected,
    Approved,
    LeftParked,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ParkedRequestResolution {
    pub parked_request_identifier: ParkedRequestIdentifier,
    pub intercept_policy_identifier: InterceptPolicyIdentifier,
    pub parked_request_outcome: ParkedRequestOutcome,
    pub approval_audit_source: ApprovalAuditSource,
    pub timestamp_nanos: TimestampNanos,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum RoundPhase {
    Commit,
    Request,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ParkedAuthorizationSnapshot {
    pub parked_authorization_vector: std::vec::Vec<ParkedAuthorization>,
}
#[rustfmt::skip]
pub type ContractName = String;
#[rustfmt::skip]
pub type RootAnchorDigest = signal::ObjectDigest;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ParkedSpiritRequest {
    pub parked_request_identifier: ParkedRequestIdentifier,
    pub intercept_policy_identifier: InterceptPolicyIdentifier,
    pub mentci_session_slot: MentciSessionSlot,
    pub spirit_authorization_context: SpiritAuthorizationContext,
    pub first_timestamp_nanos: TimestampNanos,
    pub second_timestamp_nanos: TimestampNanos,
    pub expiry_action: ExpiryAction,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct QuorumRoundState {
    pub quorum_round_identifier: QuorumRoundIdentifier,
    pub round_phase: RoundPhase,
    pub contract_digest: ContractDigest,
    pub quorum_round_status: QuorumRoundStatus,
    pub first_required_signature_threshold: RequiredSignatureThreshold,
    pub second_required_signature_threshold: RequiredSignatureThreshold,
    pub evidence_option: Option<Evidence>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationGrant {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub authorized_object_reference: signal::AuthorizedObjectReference,
    pub authorization_policy_satisfaction: AuthorizationPolicySatisfaction,
    pub signature_authorization_result: SignatureAuthorizationResult,
    pub stamped_signature_envelope_vector: std::vec::Vec<StampedSignatureEnvelope>,
    pub identity: Identity,
    pub timestamp_nanos: TimestampNanos,
    pub timestamp_nanos_option: Option<TimestampNanos>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct DueContractChecksEvaluated {
    pub authorized_object_update_vector: std::vec::Vec<AuthorizedObjectUpdate>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct NodePublicKeyObservation {}
#[rustfmt::skip]
pub type PolicyDurationNanos = i64;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationDenial {
    pub authorization_denial_source: AuthorizationDenialSource,
    pub authorization_denial_reason: AuthorizationDenialReason,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct IdentityReceipt {
    pub identity: Identity,
    pub principal_status: PrincipalStatus,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum AuthorizationDenialReason {
    SignatureScopeMismatch,
    SignerUnavailable,
    RequiredSignatureMissing,
    SignatureExpired,
    SignatureRejected,
    PolicyRefused,
    RequestDigestMismatch,
    SignerThresholdRejected,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ObjectCoSignature {
    pub authorized_object_reference: signal::AuthorizedObjectReference,
    pub identity: Identity,
    pub stamped_signature_envelope: StampedSignatureEnvelope,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationEvaluation {
    pub contract_digest: ContractDigest,
    pub authorized_object_reference: signal::AuthorizedObjectReference,
    pub evidence: Evidence,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct IdentityUpdate {
    pub identity_receipt: IdentityReceipt,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum PolicyMember {
    ObjectMember(ContractDigest),
    KeyMember(Identity),
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct DelegationGrant {
    pub first_identity: Identity,
    pub second_identity: Identity,
    pub content_purpose: ContentPurpose,
    pub timestamp_nanos_option: Option<TimestampNanos>,
}
#[rustfmt::skip]
pub type ContractDigest = signal::ObjectDigest;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum SignatureAuthorizationResult {
    Expired,
    Rejected,
    PendingSignatures,
    RequiredSignaturesSatisfied,
    SingleSignature,
}
#[rustfmt::skip]
pub type InterceptPolicies = std::vec::Vec<InterceptPolicy>;
#[rustfmt::skip]
pub type MentciSessionSlot = String;
#[rustfmt::skip]
pub type ContractOperationHead = String;
#[rustfmt::skip]
pub type ActorIdentifier = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizedObjectUpdateRetracted {
    pub authorized_object_update_token: AuthorizedObjectUpdateToken,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct QuorumShortfall {
    pub first_required_signature_threshold: RequiredSignatureThreshold,
    pub second_required_signature_threshold: RequiredSignatureThreshold,
}
#[rustfmt::skip]
pub type PrincipalName = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct Threshold {
    pub required_signature_threshold: RequiredSignatureThreshold,
    pub policy_member_vector: std::vec::Vec<PolicyMember>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum Rule {
    Timed(TimeSwitch),
    Any(std::vec::Vec<ContractDigest>),
    All(std::vec::Vec<ContractDigest>),
    ActiveAfter(TimedRule),
    SignedBy(Identity),
    Workflow(WorkflowGuard),
    Agreement(AgreementRule),
    ActiveUntil(TimedRule),
    Composite(Composition),
    ThresholdRule(Threshold),
    EscalateToPsyche,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct CriomeDaemonConfiguration {
    pub first_daemon_path: DaemonPath,
    pub second_daemon_path: DaemonPath,
    pub daemon_path_option: Option<DaemonPath>,
    pub bls_public_key_option: Option<BlsPublicKey>,
    pub authorization_mode: AuthorizationMode,
    pub identity_option: Option<Identity>,
    pub router_submission_configuration_option: Option<RouterSubmissionConfiguration>,
    pub quorum_window_nanos_option: Option<QuorumWindowNanos>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct IdentitySnapshot {
    pub identity_receipt_vector: std::vec::Vec<IdentityReceipt>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct Rejection {
    pub rejection_reason: RejectionReason,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationObservationRetracted {
    pub authorization_observation_token: AuthorizationObservationToken,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct FoundingConveyanceReceipt {
    pub root_anchor_digest: RootAnchorDigest,
    pub founding_conveyance_outcome: FoundingConveyanceOutcome,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct Attestation {
    pub content_reference: ContentReference,
    pub identity: Identity,
    pub signature_envelope: SignatureEnvelope,
    pub timestamp_nanos: TimestampNanos,
    pub timestamp_nanos_option: Option<TimestampNanos>,
    pub audit_context: AuditContext,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct IdentitySubscriptionToken {
    pub identity: Identity,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizedObjectUpdateSnapshot {
    pub authorized_object_update_vector: std::vec::Vec<AuthorizedObjectUpdate>,
}
#[rustfmt::skip]
pub type SpiritProcessKey = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum ContentPurpose {
    ChannelGrant,
    SignedObject,
    ChannelRetract,
    PrivilegeElevation,
    Authorization,
    Archive,
    ComponentRelease,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ContentReference {
    pub object_digest: signal::ObjectDigest,
    pub content_purpose: ContentPurpose,
    pub principal_name: PrincipalName,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct VerificationResult {
    pub verification_decision: VerificationDecision,
    pub identity_option: Option<Identity>,
    pub timestamp_nanos_option: Option<TimestampNanos>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct Contract {
    pub rule: Rule,
    pub contract_parent: ContractParent,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SignatureSolicitation {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub object_digest: signal::ObjectDigest,
    pub contract_name: ContractName,
    pub contract_operation_head: ContractOperationHead,
    pub authorization_scope: AuthorizationScope,
    pub first_identity: Identity,
    pub second_identity: Identity,
}
#[rustfmt::skip]
pub type DaemonPath = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationExpired {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub timestamp_nanos: TimestampNanos,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum QuorumRoundStatus {
    Authorized,
    Gathering,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct IdentityRegistration {
    pub identity: Identity,
    pub bls_public_key: BlsPublicKey,
    pub public_key_fingerprint: PublicKeyFingerprint,
    pub key_purpose: KeyPurpose,
    pub signature_envelope_option: Option<SignatureEnvelope>,
}
#[rustfmt::skip]
pub type PolicyPriority = i64;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ContractAdmitted {
    pub contract_digest: ContractDigest,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct InterceptPolicyProposal {
    pub mentci_session_slot: MentciSessionSlot,
    pub intercept_target_selector: InterceptTargetSelector,
    pub spirit_operation_names: SpiritOperationNames,
    pub policy_duration_nanos: PolicyDurationNanos,
    pub expiry_action: ExpiryAction,
    pub policy_priority: PolicyPriority,
    pub policy_overlap_mode: PolicyOverlapMode,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum ContractParent {
    Root,
    Parent(ContractDigest),
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ParkedAuthorizationObservation {}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ContractTimeCheck {
    pub contract_digest: ContractDigest,
    pub timestamp_nanos: TimestampNanos,
    pub authorized_object_reference: signal::AuthorizedObjectReference,
    pub authorized_object_interest: signal::AuthorizedObjectInterest,
}
#[rustfmt::skip]
pub type CompositionDigest = signal::ObjectDigest;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ContractMissing {
    pub contract_digest: ContractDigest,
}
#[rustfmt::skip]
pub type AuthorizationScope = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ArchiveAttestationRequest {
    pub component_release_record: ComponentReleaseRecord,
    pub audit_context: AuditContext,
}
#[rustfmt::skip]
pub type RawSpiritOperationPayload = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct PeerActorRoute {
    pub identity: Identity,
    pub actor_identifier: ActorIdentifier,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct FoundingSignature {
    pub identity: Identity,
    pub signature_envelope: SignatureEnvelope,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum AuthorizationDenialSource {
    Signers,
    Policy,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SignatureSubmissionReceipt {
    pub authorization_request_slot: AuthorizationRequestSlot,
    pub identity: Identity,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationObservationSnapshot {
    pub authorization_state_record_vector: std::vec::Vec<AuthorizationStateRecord>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ContractAdmissionRejected {
    pub contract_admission_rejection_reason: ContractAdmissionRejectionReason,
}
#[rustfmt::skip]
pub type TimestampNanos = i64;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ParkedRequestSnapshot {
    pub parked_spirit_requests: ParkedSpiritRequests,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct QuorumVoteSolicitation {
    pub quorum_round_identifier: QuorumRoundIdentifier,
    pub round_phase: RoundPhase,
    pub contract_digest: ContractDigest,
    pub authorized_object_reference: signal::AuthorizedObjectReference,
    pub attested_moment_proposition: AttestedMomentProposition,
    pub identity: Identity,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct CoSignatureExpectation {
    pub authorized_object_reference: signal::AuthorizedObjectReference,
    pub first_identity_vector: std::vec::Vec<Identity>,
    pub second_identity_vector: std::vec::Vec<Identity>,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct InterceptTargetSelector {
    pub spirit_process_key: SpiritProcessKey,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct SignatureSolicitationRoute {
    pub signature_solicitation: SignatureSolicitation,
    pub identity: Identity,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct NodePublicKey {
    pub bls_public_key: BlsPublicKey,
}
#[rustfmt::skip]
pub type PublicKeyFingerprint = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct TimeSwitch {
    pub timestamp_nanos: TimestampNanos,
    pub first_threshold: Threshold,
    pub second_threshold: Threshold,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct TimeWindow {
    pub first_timestamp_nanos: TimestampNanos,
    pub second_timestamp_nanos: TimestampNanos,
}
#[rustfmt::skip]
pub type InterceptPolicyIdentifier = String;
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ParkedRequestAnswer {
    pub parked_request_identifier: ParkedRequestIdentifier,
    pub parked_request_decision: ParkedRequestDecision,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct InterceptPolicyCancellation {
    pub intercept_policy_identifier: InterceptPolicyIdentifier,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AuthorizationObservationToken {
    pub authorization_request_slot: AuthorizationRequestSlot,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum GenesisDomainTag {
    CriomeRootFoundingV1,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct ChannelGrantAttestationRequest {
    pub content_reference: ContentReference,
    pub identity: Identity,
    pub audit_context: AuditContext,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub struct AgreementFact {
    pub first_object_digest: signal::ObjectDigest,
    pub second_object_digest: signal::ObjectDigest,
    pub identity: Identity,
    pub stamped_signature_envelope: StampedSignatureEnvelope,
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum Query {
    RouteSignatureRequest(SignatureSolicitationRoute),
    AuthorizeSignalCall(SignalCallAuthorization),
    SubscribeIdentityUpdates(IdentitySubscription),
    RegisterIdentity(IdentityRegistration),
    EvaluateAuthorization(AuthorizationEvaluation),
    VerifyAuthorization(AuthorizationVerification),
    ConveyFounding(FoundingConveyance),
    ProposeQuorumAuthorization(QuorumProposal),
    ObserveAuthorization(AuthorizationObservation),
    AttestChannelGrant(ChannelGrantAttestationRequest),
    LookupContract(ContractDigest),
    SubmitQuorumVote(QuorumVote),
    AdmitContract(Contract),
    ObserveQuorumRound(QuorumRoundQuery),
    RejectAuthorization(AuthorizationRejection),
    ObserveAuthorizedObjects(AuthorizedObjectObservation),
    SolicitQuorumVote(QuorumVoteSolicitation),
    LookupIdentity(IdentityLookup),
    RunDueContractChecks(AttestedMoment),
    RevokeIdentity(IdentityRevocation),
    AuthorizationObservationRetraction(AuthorizationObservationToken),
    ObserveParkedAuthorizations(ParkedAuthorizationObservation),
    AuthorizedObjectUpdateRetraction(AuthorizedObjectUpdateToken),
    AttestArchive(ArchiveAttestationRequest),
    Sign(SignRequest),
    SubmitSignature(SignatureSubmission),
    VerifyAttestation(VerifyRequest),
    IdentitySubscriptionRetraction(IdentitySubscriptionToken),
    ScheduleContractTimeCheck(ContractTimeCheck),
    ObserveNodePublicKey(NodePublicKeyObservation),
    AttestAuthorization(AuthorizationAttestationRequest),
}
#[rustfmt::skip]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "datom", derive(datom_codec::Datomizable, datom_codec::Composing))]
pub enum Response {
    QuorumRoundObserved(QuorumRoundState),
    QuorumVoteAccepted(QuorumRoundState),
    ParkedAuthorizations(ParkedAuthorizationSnapshot),
    SignatureRouted(SignatureRouteReceipt),
    AuthorizationObservationClosed(AuthorizationObservationRetracted),
    PublicKeyObserved(NodePublicKey),
    FoundingConveyed(FoundingConveyanceReceipt),
    AuthorizedObjectRetracted(AuthorizedObjectUpdateRetracted),
    SubscriptionClosed(SubscriptionRetracted),
    AuthorizationGranted(AuthorizationGrant),
    ContractAbsent(ContractMissing),
    QuorumRefused(QuorumConflict),
    Attested(AttestationReceipt),
    Verified(VerificationResult),
    Pending(AuthorizationPending),
    AuthorizationObserved(AuthorizationObservationSnapshot),
    Unavailable(AuthorizationUnavailable),
    Denied(AuthorizationDenied),
    IdentityRegistered(IdentityReceipt),
    Signed(SignReceipt),
    Identities(IdentitySnapshot),
    ContractLocated(ContractFound),
    TimeCheckScheduled(ContractTimeCheckScheduled),
    AuthorizedObjectsUpdated(AuthorizedObjectUpdateSnapshot),
    ContractRefused(ContractAdmissionRejected),
    SignatureSubmitted(SignatureSubmissionReceipt),
    AuthorizationJudged(AuthorizationEvaluated),
    Expired(AuthorizationExpired),
    ContractAccepted(ContractAdmitted),
    DueChecksEvaluated(DueContractChecksEvaluated),
    Refused(Rejection),
    QuorumVoteSolicited(QuorumRoundState),
    QuorumRoundOpened(QuorumRoundState),
}
