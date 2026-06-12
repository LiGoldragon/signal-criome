//! Schema-derived Signal contract for Criome trust and attestation records.
//!
//! Wire-only vocabulary emitted from `schema/lib.schema`. This module adds the
//! hand-written escape-hatch methods over the emitted types (string accessors,
//! digest hashing, integer projections, and the daemon-configuration rkyv
//! helpers) plus the criome-named channel type aliases.

#[rustfmt::skip]
#[allow(clippy::large_enum_variant)]
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
    ReplayNonce,
    ContractName,
    AuthorizationRequestSlot,
    AuthorizationScope,
    ContractOperationHead,
);

impl ObjectDigest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(blake3::hash(bytes).to_hex().to_string())
    }
}

impl Copy for TimestampNanos {}
impl Copy for RequiredSignatureThreshold {}

impl TimestampNanos {
    pub fn into_u64(self) -> u64 {
        self.into_payload()
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
