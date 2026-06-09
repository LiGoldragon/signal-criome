//! Signal contract for Criome trust and attestation records.
//!
//! This crate is pure vocabulary. It carries no daemon, actor runtime,
//! transport, database, or signing implementation.

use nota_next::{Block, Delimiter, NotaBlock, NotaDecode, NotaDecodeError, NotaEncode};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use signal_frame::signal_channel;

/// A filesystem path the criome daemon binds or opens. Typed so daemon
/// configuration carries no bare `String` paths.
#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq, Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct DaemonPath(String);

impl DaemonPath {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Binary startup and meta `Configure` payload for the criome daemon: where it
/// binds its socket and where its `criome.sema` store lives. Defined in the
/// contract (not the daemon) so the daemon's startup decode and
/// `meta-signal-criome`'s `Configure` operation share one record.
#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct CriomeDaemonConfiguration {
    pub socket_path: DaemonPath,
    pub store_path: DaemonPath,
}

impl CriomeDaemonConfiguration {
    pub fn new(socket_path: impl Into<String>, store_path: impl Into<String>) -> Self {
        Self {
            socket_path: DaemonPath::new(socket_path),
            store_path: DaemonPath::new(store_path),
        }
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

#[derive(Debug, thiserror::Error)]
pub enum CriomeDaemonConfigurationArchiveError {
    #[error("failed to encode criome daemon configuration archive")]
    Encode,

    #[error("failed to decode criome daemon configuration archive")]
    Decode,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct PrincipalName(String);

impl PrincipalName {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct PrincipalId(String);

impl PrincipalId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct PublicKeyFingerprint(String);

impl PublicKeyFingerprint {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct BlsPublicKey(String);

impl BlsPublicKey {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct BlsSignature(String);

impl BlsSignature {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ObjectDigest(String);

impl ObjectDigest {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).to_hex().to_string())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ReplayNonce(String);

impl ReplayNonce {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ContractName(String);

impl ContractName {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationRequestSlot(String);

impl AuthorizationRequestSlot {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationScope(String);

impl AuthorizationScope {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct TimestampNanos(u64);

impl TimestampNanos {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn into_u64(self) -> u64 {
        self.0
    }
}

impl NotaEncode for TimestampNanos {
    fn to_nota(&self) -> String {
        self.0.to_nota()
    }
}

impl NotaDecode for TimestampNanos {
    fn from_nota_block(block: &Block) -> Result<Self, NotaDecodeError> {
        Ok(Self(u64::from_nota_block(block)?))
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum SignatureScheme {
    Bls12_381MinPk,
    Bls12_381MinSig,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ContractOperationHead(String);

impl ContractOperationHead {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum PrincipalStatus {
    Active,
    Revoked,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum KeyPurpose {
    CriomeRoot,
    PersonaRequest,
    AgentRequest,
    ReleaseAuthorization,
    HostPublication,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum ContentPurpose {
    SignedObject,
    ComponentRelease,
    ChannelGrant,
    ChannelRetract,
    Authorization,
    Archive,
    PrivilegeElevation,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum VerificationDecision {
    Valid,
    InvalidSignature,
    UnknownSigner,
    Expired,
    Revoked,
    ReplayAttempted,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum SignatureAuthorizationResult {
    SingleSignature,
    RequiredSignaturesSatisfied,
    PendingSignatures,
    Rejected,
    Expired,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct RequiredSignatureThreshold(u16);

impl RequiredSignatureThreshold {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn into_u16(self) -> u16 {
        self.0
    }
}

impl NotaEncode for RequiredSignatureThreshold {
    fn to_nota(&self) -> String {
        u64::from(self.0).to_nota()
    }
}

impl NotaDecode for RequiredSignatureThreshold {
    fn from_nota_block(block: &Block) -> Result<Self, NotaDecodeError> {
        let value = u64::from_nota_block(block)?;
        let threshold = u16::try_from(value).map_err(|_| NotaDecodeError::InvalidInteger {
            value: value.to_string(),
        })?;
        Ok(Self(threshold))
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum AuthorizationPolicyClass {
    SimpleSelfSigned,
    ComplexQuorum,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationPolicySatisfaction {
    pub policy_class: AuthorizationPolicyClass,
    pub required_signature_threshold: RequiredSignatureThreshold,
    pub satisfied_signers: Vec<Identity>,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum AuthorizationStatus {
    Pending,
    Signing,
    Granted,
    Denied,
    Expired,
    Unavailable,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum AuthorizationDenialReason {
    PolicyRefused,
    RequiredSignatureMissing,
    SignatureRejected,
    SignerThresholdRejected,
    SignatureExpired,
    RequestDigestMismatch,
    SignatureScopeMismatch,
    SignerUnavailable,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum AuthorizationDenialSource {
    Policy,
    Signers,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationDenial {
    pub source: AuthorizationDenialSource,
    pub reason: AuthorizationDenialReason,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    NotaEncode,
    NotaDecode,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum RejectionReason {
    MalformedRequest,
    UnsupportedSignatureScheme,
    UnknownIdentity,
    RevokedIdentity,
    DuplicateIdentity,
    ReplayAttempted,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, RkyvSerialize, RkyvDeserialize)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum Identity {
    Persona(PrincipalName),
    Agent(PrincipalName),
    Host(PrincipalName),
    Developer(PrincipalName),
    Cluster(PrincipalName),
}

impl Identity {
    pub fn persona(name: impl Into<String>) -> Self {
        Self::Persona(PrincipalName::new(name))
    }

    pub fn agent(name: impl Into<String>) -> Self {
        Self::Agent(PrincipalName::new(name))
    }

    pub fn host(name: impl Into<String>) -> Self {
        Self::Host(PrincipalName::new(name))
    }

    pub fn developer(name: impl Into<String>) -> Self {
        Self::Developer(PrincipalName::new(name))
    }

    pub fn cluster(name: impl Into<String>) -> Self {
        Self::Cluster(PrincipalName::new(name))
    }
}

impl NotaEncode for Identity {
    fn to_nota(&self) -> String {
        match self {
            Self::Persona(name) => Self::variant_to_nota("Persona", name),
            Self::Agent(name) => Self::variant_to_nota("Agent", name),
            Self::Host(name) => Self::variant_to_nota("Host", name),
            Self::Developer(name) => Self::variant_to_nota("Developer", name),
            Self::Cluster(name) => Self::variant_to_nota("Cluster", name),
        }
    }
}

impl NotaDecode for Identity {
    fn from_nota_block(block: &Block) -> Result<Self, NotaDecodeError> {
        let fields =
            NotaBlock::new(block).expect_children(Delimiter::Parenthesis, "Identity", 2)?;
        let head = fields[0]
            .demote_to_string()
            .ok_or(NotaDecodeError::ExpectedAtom {
                type_name: "Identity",
            })?;
        match head {
            "Persona" => Self::variant_from_nota(&fields[1], Self::Persona),
            "Agent" => Self::variant_from_nota(&fields[1], Self::Agent),
            "Host" => Self::variant_from_nota(&fields[1], Self::Host),
            "Developer" => Self::variant_from_nota(&fields[1], Self::Developer),
            "Cluster" => Self::variant_from_nota(&fields[1], Self::Cluster),
            other => Err(NotaDecodeError::UnknownVariant {
                enum_name: "Identity",
                variant: other.to_owned(),
            }),
        }
    }
}

impl Identity {
    fn variant_to_nota(head: &'static str, name: &PrincipalName) -> String {
        Delimiter::Parenthesis.wrap([head.to_owned(), name.to_nota()])
    }

    fn variant_from_nota(
        block: &Block,
        constructor: fn(PrincipalName) -> Identity,
    ) -> Result<Self, NotaDecodeError> {
        Ok(constructor(PrincipalName::from_nota_block(block)?))
    }
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ContentReference {
    pub digest: ObjectDigest,
    pub purpose: ContentPurpose,
    pub schema_version: PrincipalName,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuditContext {
    pub purpose: ContentPurpose,
    pub audience: PrincipalName,
    pub policy_version: PrincipalName,
    pub nonce: ReplayNonce,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignatureEnvelope {
    pub scheme: SignatureScheme,
    pub public_key: BlsPublicKey,
    pub signature: BlsSignature,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct Attestation {
    pub content: ContentReference,
    pub signer: Identity,
    pub envelope: SignatureEnvelope,
    pub issued_at: TimestampNanos,
    pub expires_at: Option<TimestampNanos>,
    pub audit_context: AuditContext,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignedObject {
    pub content: ContentReference,
    pub signer: Identity,
    pub envelope: SignatureEnvelope,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct DelegationGrant {
    pub issuer: Identity,
    pub subject: Identity,
    pub scope: ContentPurpose,
    pub expires_at: Option<TimestampNanos>,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ComponentRelease {
    pub component: PrincipalName,
    pub artifact: ObjectDigest,
    pub authorized_by: Identity,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignedPersonaRequest {
    pub audience: Identity,
    pub content: ContentReference,
    pub delegation: Option<DelegationGrant>,
    pub envelope: SignatureEnvelope,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignalCallAuthorization {
    pub request_digest: ObjectDigest,
    pub contract: ContractName,
    pub operation: ContractOperationHead,
    pub scope: AuthorizationScope,
    pub requester: Identity,
    pub nonce: ReplayNonce,
    pub expires_at: Option<TimestampNanos>,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationObservation {
    pub request_slot: AuthorizationRequestSlot,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationVerification {
    pub request_digest: ObjectDigest,
    pub authorization: AuthorizationGrant,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignatureSolicitation {
    pub request_slot: AuthorizationRequestSlot,
    pub request_digest: ObjectDigest,
    pub contract: ContractName,
    pub operation: ContractOperationHead,
    pub scope: AuthorizationScope,
    pub requester: Identity,
    pub required_signer: Identity,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignatureSolicitationRoute {
    pub solicitation: SignatureSolicitation,
    pub routed_to: Identity,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignatureSubmission {
    pub request_slot: AuthorizationRequestSlot,
    pub signer: Identity,
    pub envelope: SignatureEnvelope,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationRejection {
    pub request_slot: AuthorizationRequestSlot,
    pub rejector: Identity,
    pub reason: AuthorizationDenialReason,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationGrant {
    pub request_slot: AuthorizationRequestSlot,
    pub authorized_object_digest: ObjectDigest,
    pub authorized_contract: ContractName,
    pub authorized_operation: ContractOperationHead,
    pub authorization_scope: AuthorizationScope,
    pub policy_satisfaction: AuthorizationPolicySatisfaction,
    pub signature_result: SignatureAuthorizationResult,
    pub signatures: Vec<SignatureEnvelope>,
    pub issued_by: Identity,
    pub issued_at: TimestampNanos,
    pub expires_at: Option<TimestampNanos>,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationPending {
    pub request_slot: AuthorizationRequestSlot,
    pub request_digest: ObjectDigest,
    pub missing_authorities: Vec<Identity>,
    pub observation_token: AuthorizationObservationToken,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationDenied {
    pub request_slot: AuthorizationRequestSlot,
    pub denial: AuthorizationDenial,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationExpired {
    pub request_slot: AuthorizationRequestSlot,
    pub expired_at: TimestampNanos,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationUnavailable {
    pub request_slot: AuthorizationRequestSlot,
    pub reason: PrincipalName,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationStateRecord {
    pub request_slot: AuthorizationRequestSlot,
    pub request_digest: ObjectDigest,
    pub status: AuthorizationStatus,
    pub missing_authorities: Vec<Identity>,
    pub grant: Option<AuthorizationGrant>,
    pub denial: Option<AuthorizationDenial>,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationObservationSnapshot {
    pub states: Vec<AuthorizationStateRecord>,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignatureRouteReceipt {
    pub request_slot: AuthorizationRequestSlot,
    pub routed_to: Identity,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignatureSubmissionReceipt {
    pub request_slot: AuthorizationRequestSlot,
    pub signer: Identity,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationObservationRetracted {
    pub token: AuthorizationObservationToken,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationObservationToken {
    pub request_slot: AuthorizationRequestSlot,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationUpdate {
    pub state: AuthorizationStateRecord,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignRequest {
    pub content: ContentReference,
    pub signer: Identity,
    pub audit_context: AuditContext,
    pub expires_at: Option<TimestampNanos>,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct VerifyRequest {
    pub attestation: Attestation,
    pub content: ContentReference,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentityRegistration {
    pub identity: Identity,
    pub public_key: BlsPublicKey,
    pub fingerprint: PublicKeyFingerprint,
    pub purpose: KeyPurpose,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentityRevocation {
    pub identity: Identity,
    pub fingerprint: PublicKeyFingerprint,
    pub reason: PrincipalName,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentityLookup {
    pub identity: Identity,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ArchiveAttestationRequest {
    pub release: ComponentRelease,
    pub audit_context: AuditContext,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ChannelGrantAttestationRequest {
    pub grant_content: ContentReference,
    pub source: Identity,
    pub audit_context: AuditContext,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationAttestationRequest {
    pub authorization_content: ContentReference,
    pub source: Identity,
    pub audit_context: AuditContext,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentitySubscription {
    pub subscriber: Identity,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignReceipt {
    pub attestation: Attestation,
    pub issued_at: TimestampNanos,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct VerificationResult {
    pub decision: VerificationDecision,
    pub identity: Option<Identity>,
    pub expires_at: Option<TimestampNanos>,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentityReceipt {
    pub identity: Identity,
    pub status: PrincipalStatus,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentitySnapshot {
    pub identities: Vec<IdentityReceipt>,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AttestationReceipt {
    pub attestation: Attestation,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentityUpdate {
    pub receipt: IdentityReceipt,
}

/// Typed acknowledgement that a subscription has been retracted.
///
/// Returned in reply to `IdentitySubscriptionRetraction`. Carries the
/// retracted token so callers can match the ack to the request they sent.
#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SubscriptionRetracted {
    pub token: IdentitySubscriptionToken,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct Rejection {
    pub reason: RejectionReason,
}

/// Per-subscription identity for the identity-updates stream.
#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEncode, NotaDecode, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentitySubscriptionToken {
    pub subscriber: Identity,
}

signal_channel! {
    channel Criome {
        operation Sign(SignRequest),
        operation VerifyAttestation(VerifyRequest),
        operation RegisterIdentity(IdentityRegistration),
        operation RevokeIdentity(IdentityRevocation),
        operation LookupIdentity(IdentityLookup),
        operation AttestArchive(ArchiveAttestationRequest),
        operation AttestChannelGrant(ChannelGrantAttestationRequest),
        operation AttestAuthorization(AuthorizationAttestationRequest),
        operation AuthorizeSignalCall(SignalCallAuthorization),
        operation ObserveAuthorization(AuthorizationObservation) opens AuthorizationObservationStream,
        operation VerifyAuthorization(AuthorizationVerification),
        operation RouteSignatureRequest(SignatureSolicitationRoute),
        operation SubmitSignature(SignatureSubmission),
        operation RejectAuthorization(AuthorizationRejection),
        operation SubscribeIdentityUpdates(IdentitySubscription) opens IdentityUpdateStream,
        operation IdentitySubscriptionRetraction(IdentitySubscriptionToken),
        operation AuthorizationObservationRetraction(AuthorizationObservationToken),
    }

    reply CriomeReply {
        SignReceipt(SignReceipt),
        VerificationResult(VerificationResult),
        IdentityReceipt(IdentityReceipt),
        IdentitySnapshot(IdentitySnapshot),
        AttestationReceipt(AttestationReceipt),
        AuthorizationPending(AuthorizationPending),
        AuthorizationGranted(AuthorizationGrant),
        AuthorizationDenied(AuthorizationDenied),
        AuthorizationExpired(AuthorizationExpired),
        AuthorizationUnavailable(AuthorizationUnavailable),
        AuthorizationObservationSnapshot(AuthorizationObservationSnapshot),
        SignatureRouteReceipt(SignatureRouteReceipt),
        SignatureSubmissionReceipt(SignatureSubmissionReceipt),
        AuthorizationObservationRetracted(AuthorizationObservationRetracted),
        SubscriptionRetracted(SubscriptionRetracted),
        Rejection(Rejection),
    }

    event CriomeEvent {
        IdentityUpdate(IdentityUpdate) belongs IdentityUpdateStream,
        AuthorizationUpdate(AuthorizationUpdate) belongs AuthorizationObservationStream,
    }

    stream IdentityUpdateStream {
        token IdentitySubscriptionToken;
        opened IdentitySnapshot;
        event IdentityUpdate;
        close IdentitySubscriptionRetraction;
    }

    stream AuthorizationObservationStream {
        token AuthorizationObservationToken;
        opened AuthorizationObservationSnapshot;
        event AuthorizationUpdate;
        close AuthorizationObservationRetraction;
    }
}

pub type CriomeRequest = Operation;
pub type CriomeFrame = Frame;
pub type CriomeFrameBody = FrameBody;
pub type CriomeReplyEnvelope = ReplyEnvelope;
pub type CriomeRequestBuilder = RequestBuilder;
pub type CriomeOperationKind = OperationKind;
pub type CriomeStreamKind = StreamKind;

impl CriomeRequest {
    pub fn operation_kind(&self) -> CriomeOperationKind {
        self.kind()
    }
}
