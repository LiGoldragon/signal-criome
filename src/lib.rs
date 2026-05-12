//! Signal contract for Criome trust and attestation records.
//!
//! This crate is pure vocabulary. It carries no daemon, actor runtime,
//! transport, database, or signing implementation.

use nota_codec::{Decoder, Encoder, NotaDecode, NotaEncode, NotaEnum, NotaRecord, NotaTransparent};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use signal_core::signal_channel;

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaTransparent, Debug, Clone, PartialEq, Eq, Hash,
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
    Archive, RkyvSerialize, RkyvDeserialize, NotaTransparent, Debug, Clone, PartialEq, Eq, Hash,
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
    Archive, RkyvSerialize, RkyvDeserialize, NotaTransparent, Debug, Clone, PartialEq, Eq, Hash,
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
    Archive, RkyvSerialize, RkyvDeserialize, NotaTransparent, Debug, Clone, PartialEq, Eq, Hash,
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
    Archive, RkyvSerialize, RkyvDeserialize, NotaTransparent, Debug, Clone, PartialEq, Eq, Hash,
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
    Archive, RkyvSerialize, RkyvDeserialize, NotaTransparent, Debug, Clone, PartialEq, Eq, Hash,
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
    Archive, RkyvSerialize, RkyvDeserialize, NotaTransparent, Debug, Clone, PartialEq, Eq, Hash,
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
    NotaTransparent,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
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

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEnum, Debug, Clone, Copy, PartialEq, Eq, Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum SignatureScheme {
    Bls12_381MinPk,
    Bls12_381MinSig,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEnum, Debug, Clone, Copy, PartialEq, Eq, Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum PrincipalStatus {
    Active,
    Revoked,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, NotaEnum, Debug, Clone, Copy, PartialEq, Eq, Hash,
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
    Archive, RkyvSerialize, RkyvDeserialize, NotaEnum, Debug, Clone, Copy, PartialEq, Eq, Hash,
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
    Archive, RkyvSerialize, RkyvDeserialize, NotaEnum, Debug, Clone, Copy, PartialEq, Eq, Hash,
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
    Archive, RkyvSerialize, RkyvDeserialize, NotaEnum, Debug, Clone, Copy, PartialEq, Eq, Hash,
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
    fn encode(&self, encoder: &mut Encoder) -> nota_codec::Result<()> {
        match self {
            Self::Persona(name) => encode_identity("Persona", name, encoder),
            Self::Agent(name) => encode_identity("Agent", name, encoder),
            Self::Host(name) => encode_identity("Host", name, encoder),
            Self::Developer(name) => encode_identity("Developer", name, encoder),
            Self::Cluster(name) => encode_identity("Cluster", name, encoder),
        }
    }
}

impl NotaDecode for Identity {
    fn decode(decoder: &mut Decoder<'_>) -> nota_codec::Result<Self> {
        let head = decoder.peek_record_head()?;
        match head.as_str() {
            "Persona" => decode_identity(decoder, "Persona", Self::Persona),
            "Agent" => decode_identity(decoder, "Agent", Self::Agent),
            "Host" => decode_identity(decoder, "Host", Self::Host),
            "Developer" => decode_identity(decoder, "Developer", Self::Developer),
            "Cluster" => decode_identity(decoder, "Cluster", Self::Cluster),
            other => Err(nota_codec::Error::UnknownKindForVerb {
                verb: "Identity",
                got: other.to_string(),
            }),
        }
    }
}

fn encode_identity(
    head: &str,
    name: &PrincipalName,
    encoder: &mut Encoder,
) -> nota_codec::Result<()> {
    encoder.start_record(head)?;
    name.encode(encoder)?;
    encoder.end_record()
}

fn decode_identity(
    decoder: &mut Decoder<'_>,
    head: &'static str,
    constructor: fn(PrincipalName) -> Identity,
) -> nota_codec::Result<Identity> {
    decoder.expect_record_head(head)?;
    let name = PrincipalName::decode(decoder)?;
    decoder.expect_record_end()?;
    Ok(constructor(name))
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ContentReference {
    pub digest: ObjectDigest,
    pub purpose: ContentPurpose,
    pub schema_version: PrincipalName,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuditContext {
    pub purpose: ContentPurpose,
    pub audience: PrincipalName,
    pub policy_version: PrincipalName,
    pub nonce: ReplayNonce,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignatureEnvelope {
    pub scheme: SignatureScheme,
    pub public_key: BlsPublicKey,
    pub signature: BlsSignature,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct Attestation {
    pub content: ContentReference,
    pub signer: Identity,
    pub envelope: SignatureEnvelope,
    pub issued_at: TimestampNanos,
    pub expires_at: Option<TimestampNanos>,
    pub audit_context: AuditContext,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignedObject {
    pub content: ContentReference,
    pub signer: Identity,
    pub envelope: SignatureEnvelope,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct DelegationGrant {
    pub issuer: Identity,
    pub subject: Identity,
    pub scope: ContentPurpose,
    pub expires_at: Option<TimestampNanos>,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ComponentRelease {
    pub component: PrincipalName,
    pub artifact: ObjectDigest,
    pub authorized_by: Identity,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignedPersonaRequest {
    pub audience: Identity,
    pub content: ContentReference,
    pub delegation: Option<DelegationGrant>,
    pub envelope: SignatureEnvelope,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignRequest {
    pub content: ContentReference,
    pub signer: Identity,
    pub audit_context: AuditContext,
    pub expires_at: Option<TimestampNanos>,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct VerifyRequest {
    pub attestation: Attestation,
    pub content: ContentReference,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentityRegistration {
    pub identity: Identity,
    pub public_key: BlsPublicKey,
    pub fingerprint: PublicKeyFingerprint,
    pub purpose: KeyPurpose,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentityRevocation {
    pub identity: Identity,
    pub fingerprint: PublicKeyFingerprint,
    pub reason: PrincipalName,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentityLookup {
    pub identity: Identity,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ArchiveAttestationRequest {
    pub release: ComponentRelease,
    pub audit_context: AuditContext,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ChannelGrantAttestationRequest {
    pub grant_content: ContentReference,
    pub source: Identity,
    pub audit_context: AuditContext,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AuthorizationAttestationRequest {
    pub authorization_content: ContentReference,
    pub source: Identity,
    pub audit_context: AuditContext,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentitySubscription {
    pub subscriber: Identity,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SignReceipt {
    pub attestation: Attestation,
    pub issued_at: TimestampNanos,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct VerificationResult {
    pub decision: VerificationDecision,
    pub identity: Option<Identity>,
    pub expires_at: Option<TimestampNanos>,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentityReceipt {
    pub identity: Identity,
    pub status: PrincipalStatus,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentitySnapshot {
    pub identities: Vec<IdentityReceipt>,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AttestationReceipt {
    pub attestation: Attestation,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IdentityUpdate {
    pub receipt: IdentityReceipt,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, NotaRecord, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct Rejection {
    pub reason: RejectionReason,
}

signal_channel! {
    request CriomeRequest {
        Sign(SignRequest),
        VerifyAttestation(VerifyRequest),
        RegisterIdentity(IdentityRegistration),
        RevokeIdentity(IdentityRevocation),
        LookupIdentity(IdentityLookup),
        AttestArchive(ArchiveAttestationRequest),
        AttestChannelGrant(ChannelGrantAttestationRequest),
        AttestAuthorization(AuthorizationAttestationRequest),
        SubscribeIdentityUpdates(IdentitySubscription),
    }

    reply CriomeReply {
        SignReceipt(SignReceipt),
        VerificationResult(VerificationResult),
        IdentityReceipt(IdentityReceipt),
        IdentitySnapshot(IdentitySnapshot),
        AttestationReceipt(AttestationReceipt),
        IdentityUpdate(IdentityUpdate),
        Rejection(Rejection),
    }
}
