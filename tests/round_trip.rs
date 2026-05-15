use nota_codec::{Decoder, Encoder, NotaDecode, NotaEncode};
use signal_core::{
    ExchangeIdentifier, ExchangeLane, LaneSequence, NonEmpty, Reply, RequestPayload, SessionEpoch,
    SignalVerb, StreamEventIdentifier, SubReply, SubscriptionTokenInner,
};
use signal_criome::{
    ArchiveAttestationRequest, Attestation, AttestationReceipt, AuditContext, BlsPublicKey,
    BlsSignature, ChannelGrantAttestationRequest, ComponentRelease, ContentPurpose,
    ContentReference, CriomeEvent, CriomeFrame as Frame, CriomeFrameBody as FrameBody, CriomeReply,
    CriomeRequest, Identity, IdentityLookup, IdentityReceipt, IdentityRegistration,
    IdentityRevocation, IdentitySnapshot, IdentitySubscription, IdentitySubscriptionToken,
    IdentityUpdate, KeyPurpose, ObjectDigest, PrincipalName, PrincipalStatus, PublicKeyFingerprint,
    Rejection, RejectionReason, ReplayNonce, SignReceipt, SignRequest, SignatureEnvelope,
    SignatureScheme, SubscriptionRetracted, TimestampNanos, VerificationDecision,
    VerificationResult, VerifyRequest,
};

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

fn attestation(purpose: ContentPurpose) -> Attestation {
    Attestation {
        content: content(purpose),
        signer: Identity::developer("operator"),
        envelope: envelope(),
        issued_at: TimestampNanos::new(1),
        expires_at: Some(TimestampNanos::new(2)),
        audit_context: audit(purpose),
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
    let expected_verb = request.signal_verb();
    let frame = Frame::new(FrameBody::Request {
        exchange: exchange(),
        request: request.into_request(),
    });
    let bytes = frame.encode_length_prefixed().expect("encode request");
    let decoded = Frame::decode_length_prefixed(&bytes).expect("decode request");

    match decoded.into_body() {
        FrameBody::Request { request, .. } => {
            let operation = request.operations().head();
            assert_eq!(operation.verb, expected_verb);
            operation.payload.clone()
        }
        other => panic!("expected request operation, got {other:?}"),
    }
}

fn round_trip_reply(reply: CriomeReply) -> CriomeReply {
    let frame = Frame::new(FrameBody::Reply {
        exchange: exchange(),
        reply: Reply::completed(NonEmpty::single(SubReply::Ok {
            verb: SignalVerb::Assert,
            payload: reply,
        })),
    });
    let bytes = frame.encode_length_prefixed().expect("encode reply");
    let decoded = Frame::decode_length_prefixed(&bytes).expect("decode reply");

    match decoded.into_body() {
        FrameBody::Reply { reply, .. } => match reply {
            Reply::Accepted { per_operation, .. } => match per_operation.into_head() {
                SubReply::Ok { payload, .. } => payload,
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
    let mut encoder = Encoder::new();
    value.encode(&mut encoder).expect("encode nota");
    let encoded = encoder.into_string();
    assert_eq!(encoded, expected);

    let mut decoder = Decoder::new(&encoded);
    let recovered = T::decode(&mut decoder).expect("decode nota");
    assert_eq!(recovered, value);
}

#[test]
fn request_variants_round_trip_through_length_prefixed_frame() {
    let requests = vec![
        CriomeRequest::Sign(SignRequest {
            content: content(ContentPurpose::SignedObject),
            signer: Identity::developer("operator"),
            audit_context: audit(ContentPurpose::SignedObject),
            expires_at: None,
        }),
        CriomeRequest::VerifyAttestation(VerifyRequest {
            attestation: attestation(ContentPurpose::SignedObject),
            content: content(ContentPurpose::SignedObject),
        }),
        CriomeRequest::RegisterIdentity(IdentityRegistration {
            identity: Identity::persona("designer"),
            public_key: BlsPublicKey::new("designer-public-key"),
            fingerprint: PublicKeyFingerprint::new("fingerprint-designer"),
            purpose: KeyPurpose::PersonaRequest,
        }),
        CriomeRequest::RevokeIdentity(IdentityRevocation {
            identity: Identity::persona("designer"),
            fingerprint: PublicKeyFingerprint::new("fingerprint-designer"),
            reason: PrincipalName::new("retired"),
        }),
        CriomeRequest::LookupIdentity(IdentityLookup {
            identity: Identity::host("prometheus"),
        }),
        CriomeRequest::AttestArchive(ArchiveAttestationRequest {
            release: ComponentRelease {
                component: PrincipalName::new("persona-router"),
                artifact: ObjectDigest::from_bytes(b"closure"),
                authorized_by: Identity::developer("operator"),
            },
            audit_context: audit(ContentPurpose::Archive),
        }),
        CriomeRequest::AttestChannelGrant(ChannelGrantAttestationRequest {
            grant_content: content(ContentPurpose::ChannelGrant),
            source: Identity::persona("mind"),
            audit_context: audit(ContentPurpose::ChannelGrant),
        }),
        CriomeRequest::AttestAuthorization(signal_criome::AuthorizationAttestationRequest {
            authorization_content: content(ContentPurpose::Authorization),
            source: Identity::persona("mind"),
            audit_context: audit(ContentPurpose::Authorization),
        }),
        CriomeRequest::SubscribeIdentityUpdates(IdentitySubscription {
            subscriber: Identity::agent("operator"),
        }),
        CriomeRequest::IdentitySubscriptionRetraction(IdentitySubscriptionToken {
            subscriber: Identity::agent("operator"),
        }),
    ];

    for request in requests {
        assert_eq!(round_trip_request(request.clone()), request);
    }
}

#[test]
fn request_variants_declare_expected_signal_root_verbs() {
    let cases = [
        (
            CriomeRequest::Sign(SignRequest {
                content: content(ContentPurpose::SignedObject),
                signer: Identity::developer("operator"),
                audit_context: audit(ContentPurpose::SignedObject),
                expires_at: None,
            }),
            SignalVerb::Assert,
        ),
        (
            CriomeRequest::VerifyAttestation(VerifyRequest {
                attestation: attestation(ContentPurpose::SignedObject),
                content: content(ContentPurpose::SignedObject),
            }),
            SignalVerb::Validate,
        ),
        (
            CriomeRequest::RegisterIdentity(IdentityRegistration {
                identity: Identity::persona("designer"),
                public_key: BlsPublicKey::new("designer-public-key"),
                fingerprint: PublicKeyFingerprint::new("fingerprint-designer"),
                purpose: KeyPurpose::PersonaRequest,
            }),
            SignalVerb::Assert,
        ),
        (
            CriomeRequest::RevokeIdentity(IdentityRevocation {
                identity: Identity::persona("designer"),
                fingerprint: PublicKeyFingerprint::new("fingerprint-designer"),
                reason: PrincipalName::new("retired"),
            }),
            SignalVerb::Retract,
        ),
        (
            CriomeRequest::LookupIdentity(IdentityLookup {
                identity: Identity::host("prometheus"),
            }),
            SignalVerb::Match,
        ),
        (
            CriomeRequest::AttestArchive(ArchiveAttestationRequest {
                release: ComponentRelease {
                    component: PrincipalName::new("persona-router"),
                    artifact: ObjectDigest::from_bytes(b"closure"),
                    authorized_by: Identity::developer("operator"),
                },
                audit_context: audit(ContentPurpose::Archive),
            }),
            SignalVerb::Assert,
        ),
        (
            CriomeRequest::AttestChannelGrant(ChannelGrantAttestationRequest {
                grant_content: content(ContentPurpose::ChannelGrant),
                source: Identity::persona("mind"),
                audit_context: audit(ContentPurpose::ChannelGrant),
            }),
            SignalVerb::Assert,
        ),
        (
            CriomeRequest::AttestAuthorization(signal_criome::AuthorizationAttestationRequest {
                authorization_content: content(ContentPurpose::Authorization),
                source: Identity::persona("mind"),
                audit_context: audit(ContentPurpose::Authorization),
            }),
            SignalVerb::Assert,
        ),
        (
            CriomeRequest::SubscribeIdentityUpdates(IdentitySubscription {
                subscriber: Identity::agent("operator"),
            }),
            SignalVerb::Subscribe,
        ),
        (
            CriomeRequest::IdentitySubscriptionRetraction(IdentitySubscriptionToken {
                subscriber: Identity::agent("operator"),
            }),
            SignalVerb::Retract,
        ),
    ];

    for (request, verb) in cases {
        assert_eq!(request.signal_verb(), verb);
    }
}

#[test]
fn reply_variants_round_trip_through_length_prefixed_frame() {
    let receipt = IdentityReceipt {
        identity: Identity::persona("designer"),
        status: PrincipalStatus::Active,
    };
    let replies = vec![
        CriomeReply::SignReceipt(SignReceipt {
            attestation: attestation(ContentPurpose::SignedObject),
            issued_at: TimestampNanos::new(1),
        }),
        CriomeReply::VerificationResult(VerificationResult {
            decision: VerificationDecision::Valid,
            identity: Some(Identity::developer("operator")),
            expires_at: Some(TimestampNanos::new(2)),
        }),
        CriomeReply::IdentityReceipt(receipt.clone()),
        CriomeReply::IdentitySnapshot(IdentitySnapshot {
            identities: vec![receipt.clone()],
        }),
        CriomeReply::AttestationReceipt(AttestationReceipt {
            attestation: attestation(ContentPurpose::Archive),
        }),
        CriomeReply::SubscriptionRetracted(SubscriptionRetracted {
            token: IdentitySubscriptionToken {
                subscriber: Identity::agent("operator"),
            },
        }),
        CriomeReply::Rejection(Rejection {
            reason: RejectionReason::ReplayAttempted,
        }),
    ];

    for reply in replies {
        assert_eq!(round_trip_reply(reply.clone()), reply);
    }
}

#[test]
fn identity_update_event_round_trips_through_length_prefixed_frame() {
    let receipt = IdentityReceipt {
        identity: Identity::persona("designer"),
        status: PrincipalStatus::Active,
    };
    let event = CriomeEvent::IdentityUpdate(IdentityUpdate { receipt });
    assert_eq!(round_trip_event(event.clone()), event);
}

#[test]
fn root_request_round_trips_through_nota_text() {
    round_trip_nota(
        CriomeRequest::LookupIdentity(IdentityLookup {
            identity: Identity::persona("designer"),
        }),
        "(IdentityLookup (Persona designer))",
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
        "(VerificationResult UnknownSigner None None)",
    );
}

#[test]
fn signature_scheme_is_bls_only() {
    let source = std::fs::read_to_string("src/lib.rs").expect("read source");

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
