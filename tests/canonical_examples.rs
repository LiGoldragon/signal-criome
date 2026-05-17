//! Canonical examples round-trip witness.
//!
//! Parses `examples/canonical.nota` end-to-end, decoding each record
//! through its NOTA codec and asserting the re-encoded text equals
//! the canonical form. The selection covers the Path A lifecycle
//! and one example per request/reply family. Exhaustive per-variant
//! round-trip witnesses already live in `tests/round_trip.rs`.

use nota_codec::{Decoder, Encoder, NotaDecode, NotaEncode};
use signal_criome::{
    ArchiveAttestationRequest, Attestation, AttestationReceipt, AuditContext,
    AuthorizationAttestationRequest, AuthorizationDenial, AuthorizationDenialReason,
    AuthorizationDenialSource, AuthorizationDenied, AuthorizationExpired, AuthorizationGrant,
    AuthorizationObservation, AuthorizationObservationRetracted, AuthorizationObservationSnapshot,
    AuthorizationObservationToken, AuthorizationPending, AuthorizationPolicyClass,
    AuthorizationPolicySatisfaction, AuthorizationRejection, AuthorizationRequestSlot,
    AuthorizationScope, AuthorizationStateRecord, AuthorizationStatus, AuthorizationUnavailable,
    AuthorizationUpdate, AuthorizationVerification, AuthorizedSignalVerb, BlsPublicKey,
    BlsSignature, ChannelGrantAttestationRequest, ComponentRelease, ContentPurpose,
    ContentReference, ContractName, CriomeEvent, CriomeReply, CriomeRequest, Identity,
    IdentityLookup, IdentityReceipt, IdentityRegistration, IdentityRevocation, IdentitySnapshot,
    IdentitySubscription, IdentitySubscriptionToken, IdentityUpdate, KeyPurpose, ObjectDigest,
    PrincipalName, PrincipalStatus, PublicKeyFingerprint, Rejection, RejectionReason, ReplayNonce,
    RequiredSignatureThreshold, SignReceipt, SignRequest, SignalCallAuthorization,
    SignatureAuthorizationResult, SignatureEnvelope, SignatureRouteReceipt, SignatureScheme,
    SignatureSolicitation, SignatureSolicitationRoute, SignatureSubmission,
    SignatureSubmissionReceipt, SubscriptionRetracted, TimestampNanos, VerificationDecision,
    VerificationResult, VerifyRequest,
};

const CANONICAL: &str = include_str!("../examples/canonical.nota");

fn alice() -> Identity {
    Identity::Persona(PrincipalName::new("alice"))
}

fn content_reference() -> ContentReference {
    ContentReference {
        digest: ObjectDigest::new("digest-abc"),
        purpose: ContentPurpose::SignedObject,
        schema_version: PrincipalName::new("schema-1"),
    }
}

fn audit_context() -> AuditContext {
    AuditContext {
        purpose: ContentPurpose::SignedObject,
        audience: PrincipalName::new("audience-bob"),
        policy_version: PrincipalName::new("policy-1"),
        nonce: ReplayNonce::new("nonce-7"),
    }
}

fn envelope() -> SignatureEnvelope {
    SignatureEnvelope {
        scheme: SignatureScheme::Bls12_381MinPk,
        public_key: BlsPublicKey::new("public-key-1"),
        signature: BlsSignature::new("signature-1"),
    }
}

fn attestation() -> Attestation {
    Attestation {
        content: content_reference(),
        signer: alice(),
        envelope: envelope(),
        issued_at: TimestampNanos::new(100),
        expires_at: None,
        audit_context: audit_context(),
    }
}

fn token() -> IdentitySubscriptionToken {
    IdentitySubscriptionToken {
        subscriber: alice(),
    }
}

fn authorization_request_slot() -> AuthorizationRequestSlot {
    AuthorizationRequestSlot::new("authorization-request-1")
}

fn authorization_observation_token() -> AuthorizationObservationToken {
    AuthorizationObservationToken {
        request_slot: authorization_request_slot(),
    }
}

fn contract_name() -> ContractName {
    ContractName::new("signal-lojix")
}

fn authorization_scope() -> AuthorizationScope {
    AuthorizationScope::new("deploy-zeus-full-os")
}

fn authorization_grant() -> AuthorizationGrant {
    AuthorizationGrant {
        authorized_object_digest: ObjectDigest::new("digest-lojix-request"),
        authorized_contract: contract_name(),
        authorized_verb: AuthorizedSignalVerb::Assert,
        authorization_scope: authorization_scope(),
        policy_satisfaction: AuthorizationPolicySatisfaction {
            policy_class: AuthorizationPolicyClass::ComplexQuorum,
            required_signature_threshold: RequiredSignatureThreshold::new(1),
            satisfied_signers: vec![Identity::Cluster(PrincipalName::new("uranus"))],
        },
        signature_result: SignatureAuthorizationResult::RequiredSignaturesSatisfied,
        signatures: vec![envelope()],
        issued_by: Identity::Cluster(PrincipalName::new("uranus")),
        issued_at: TimestampNanos::new(110),
        expires_at: None,
    }
}

fn authorization_state() -> AuthorizationStateRecord {
    AuthorizationStateRecord {
        request_slot: authorization_request_slot(),
        request_digest: ObjectDigest::new("digest-lojix-request"),
        status: AuthorizationStatus::Pending,
        missing_authorities: vec![Identity::Developer(PrincipalName::new("reviewer"))],
        grant: None,
        denial: None,
    }
}

fn signature_solicitation() -> SignatureSolicitation {
    SignatureSolicitation {
        request_slot: authorization_request_slot(),
        request_digest: ObjectDigest::new("digest-lojix-request"),
        contract: contract_name(),
        verb: AuthorizedSignalVerb::Assert,
        scope: authorization_scope(),
        requester: alice(),
        required_signer: Identity::Developer(PrincipalName::new("reviewer")),
    }
}

fn round_trip<T>(value: T, canonical_text: &str)
where
    T: NotaEncode + NotaDecode + PartialEq + std::fmt::Debug,
{
    let mut encoder = Encoder::new();
    value.encode(&mut encoder).expect("encode");
    let text = encoder.into_string();
    assert_eq!(text, canonical_text, "encode for {value:?}");

    let mut decoder = Decoder::new(canonical_text);
    let decoded = T::decode(&mut decoder).expect("decode");
    assert_eq!(decoded, value, "decode for {canonical_text}");

    assert!(
        CANONICAL.contains(canonical_text),
        "examples/canonical.nota missing line: {canonical_text}",
    );
}

#[test]
fn canonical_request_examples_round_trip() {
    round_trip(
        CriomeRequest::Sign(SignRequest {
            content: content_reference(),
            signer: alice(),
            audit_context: audit_context(),
            expires_at: None,
        }),
        "(SignRequest (ContentReference digest-abc SignedObject schema-1) (Persona alice) (AuditContext SignedObject audience-bob policy-1 nonce-7) None)",
    );
    round_trip(
        CriomeRequest::VerifyAttestation(VerifyRequest {
            attestation: attestation(),
            content: content_reference(),
        }),
        "(VerifyRequest (Attestation (ContentReference digest-abc SignedObject schema-1) (Persona alice) (SignatureEnvelope Bls12_381MinPk public-key-1 signature-1) 100 None (AuditContext SignedObject audience-bob policy-1 nonce-7)) (ContentReference digest-abc SignedObject schema-1))",
    );
    round_trip(
        CriomeRequest::RegisterIdentity(IdentityRegistration {
            identity: alice(),
            public_key: BlsPublicKey::new("public-key-1"),
            fingerprint: PublicKeyFingerprint::new("fingerprint-1"),
            purpose: KeyPurpose::PersonaRequest,
        }),
        "(IdentityRegistration (Persona alice) public-key-1 fingerprint-1 PersonaRequest)",
    );
    round_trip(
        CriomeRequest::RevokeIdentity(IdentityRevocation {
            identity: alice(),
            fingerprint: PublicKeyFingerprint::new("fingerprint-1"),
            reason: PrincipalName::new("revoked-by-owner"),
        }),
        "(IdentityRevocation (Persona alice) fingerprint-1 revoked-by-owner)",
    );
    round_trip(
        CriomeRequest::LookupIdentity(IdentityLookup { identity: alice() }),
        "(IdentityLookup (Persona alice))",
    );
    round_trip(
        CriomeRequest::AttestArchive(ArchiveAttestationRequest {
            release: ComponentRelease {
                component: PrincipalName::new("persona-router"),
                artifact: ObjectDigest::new("artifact-1"),
                authorized_by: alice(),
            },
            audit_context: AuditContext {
                purpose: ContentPurpose::Archive,
                audience: PrincipalName::new("audience-archive"),
                policy_version: PrincipalName::new("policy-1"),
                nonce: ReplayNonce::new("nonce-8"),
            },
        }),
        "(ArchiveAttestationRequest (ComponentRelease persona-router artifact-1 (Persona alice)) (AuditContext Archive audience-archive policy-1 nonce-8))",
    );
    round_trip(
        CriomeRequest::AttestChannelGrant(ChannelGrantAttestationRequest {
            grant_content: ContentReference {
                digest: ObjectDigest::new("digest-grant"),
                purpose: ContentPurpose::ChannelGrant,
                schema_version: PrincipalName::new("schema-1"),
            },
            source: alice(),
            audit_context: AuditContext {
                purpose: ContentPurpose::ChannelGrant,
                audience: PrincipalName::new("audience-bob"),
                policy_version: PrincipalName::new("policy-1"),
                nonce: ReplayNonce::new("nonce-9"),
            },
        }),
        "(ChannelGrantAttestationRequest (ContentReference digest-grant ChannelGrant schema-1) (Persona alice) (AuditContext ChannelGrant audience-bob policy-1 nonce-9))",
    );
    round_trip(
        CriomeRequest::AttestAuthorization(AuthorizationAttestationRequest {
            authorization_content: ContentReference {
                digest: ObjectDigest::new("digest-auth"),
                purpose: ContentPurpose::Authorization,
                schema_version: PrincipalName::new("schema-1"),
            },
            source: alice(),
            audit_context: AuditContext {
                purpose: ContentPurpose::Authorization,
                audience: PrincipalName::new("audience-bob"),
                policy_version: PrincipalName::new("policy-1"),
                nonce: ReplayNonce::new("nonce-10"),
            },
        }),
        "(AuthorizationAttestationRequest (ContentReference digest-auth Authorization schema-1) (Persona alice) (AuditContext Authorization audience-bob policy-1 nonce-10))",
    );
    round_trip(
        CriomeRequest::AuthorizeSignalCall(SignalCallAuthorization {
            request_digest: ObjectDigest::new("digest-lojix-request"),
            contract: contract_name(),
            verb: AuthorizedSignalVerb::Assert,
            scope: authorization_scope(),
            requester: alice(),
            nonce: ReplayNonce::new("authorization-nonce-1"),
            expires_at: None,
        }),
        "(SignalCallAuthorization digest-lojix-request signal-lojix Assert deploy-zeus-full-os (Persona alice) authorization-nonce-1 None)",
    );
    round_trip(
        CriomeRequest::ObserveAuthorization(AuthorizationObservation {
            request_slot: authorization_request_slot(),
        }),
        "(AuthorizationObservation authorization-request-1)",
    );
    round_trip(
        CriomeRequest::VerifyAuthorization(AuthorizationVerification {
            request_digest: ObjectDigest::new("digest-lojix-request"),
            authorization: authorization_grant(),
        }),
        "(AuthorizationVerification digest-lojix-request (AuthorizationGrant digest-lojix-request signal-lojix Assert deploy-zeus-full-os (AuthorizationPolicySatisfaction ComplexQuorum 1 [(Cluster uranus)]) RequiredSignaturesSatisfied [(SignatureEnvelope Bls12_381MinPk public-key-1 signature-1)] (Cluster uranus) 110 None))",
    );
    round_trip(
        CriomeRequest::RouteSignatureRequest(SignatureSolicitationRoute {
            solicitation: signature_solicitation(),
            routed_to: Identity::Host(PrincipalName::new("balboa")),
        }),
        "(SignatureSolicitationRoute (SignatureSolicitation authorization-request-1 digest-lojix-request signal-lojix Assert deploy-zeus-full-os (Persona alice) (Developer reviewer)) (Host balboa))",
    );
    round_trip(
        CriomeRequest::SubmitSignature(SignatureSubmission {
            request_slot: authorization_request_slot(),
            signer: Identity::Developer(PrincipalName::new("reviewer")),
            envelope: envelope(),
        }),
        "(SignatureSubmission authorization-request-1 (Developer reviewer) (SignatureEnvelope Bls12_381MinPk public-key-1 signature-1))",
    );
    round_trip(
        CriomeRequest::RejectAuthorization(AuthorizationRejection {
            request_slot: authorization_request_slot(),
            rejector: Identity::Developer(PrincipalName::new("reviewer")),
            reason: AuthorizationDenialReason::SignatureRejected,
        }),
        "(AuthorizationRejection authorization-request-1 (Developer reviewer) SignatureRejected)",
    );
    round_trip(
        CriomeRequest::SubscribeIdentityUpdates(IdentitySubscription {
            subscriber: alice(),
        }),
        "(IdentitySubscription (Persona alice))",
    );
    round_trip(
        CriomeRequest::IdentitySubscriptionRetraction(token()),
        "(IdentitySubscriptionToken (Persona alice))",
    );
    round_trip(
        CriomeRequest::AuthorizationObservationRetraction(authorization_observation_token()),
        "(AuthorizationObservationToken authorization-request-1)",
    );
}

#[test]
fn canonical_reply_examples_round_trip() {
    round_trip(
        CriomeReply::SignReceipt(SignReceipt {
            attestation: attestation(),
            issued_at: TimestampNanos::new(100),
        }),
        "(SignReceipt (Attestation (ContentReference digest-abc SignedObject schema-1) (Persona alice) (SignatureEnvelope Bls12_381MinPk public-key-1 signature-1) 100 None (AuditContext SignedObject audience-bob policy-1 nonce-7)) 100)",
    );
    round_trip(
        CriomeReply::VerificationResult(VerificationResult {
            decision: VerificationDecision::Valid,
            identity: Some(alice()),
            expires_at: None,
        }),
        "(VerificationResult Valid (Persona alice) None)",
    );
    round_trip(
        CriomeReply::IdentityReceipt(IdentityReceipt {
            identity: alice(),
            status: PrincipalStatus::Active,
        }),
        "(IdentityReceipt (Persona alice) Active)",
    );
    round_trip(
        CriomeReply::IdentitySnapshot(IdentitySnapshot {
            identities: vec![IdentityReceipt {
                identity: alice(),
                status: PrincipalStatus::Active,
            }],
        }),
        "(IdentitySnapshot [(IdentityReceipt (Persona alice) Active)])",
    );
    round_trip(
        CriomeReply::AttestationReceipt(AttestationReceipt {
            attestation: attestation(),
        }),
        "(AttestationReceipt (Attestation (ContentReference digest-abc SignedObject schema-1) (Persona alice) (SignatureEnvelope Bls12_381MinPk public-key-1 signature-1) 100 None (AuditContext SignedObject audience-bob policy-1 nonce-7)))",
    );
    round_trip(
        CriomeReply::AuthorizationPending(AuthorizationPending {
            request_slot: authorization_request_slot(),
            request_digest: ObjectDigest::new("digest-lojix-request"),
            missing_authorities: vec![Identity::Developer(PrincipalName::new("reviewer"))],
            observation_token: authorization_observation_token(),
        }),
        "(AuthorizationPending authorization-request-1 digest-lojix-request [(Developer reviewer)] (AuthorizationObservationToken authorization-request-1))",
    );
    round_trip(
        CriomeReply::AuthorizationGranted(authorization_grant()),
        "(AuthorizationGrant digest-lojix-request signal-lojix Assert deploy-zeus-full-os (AuthorizationPolicySatisfaction ComplexQuorum 1 [(Cluster uranus)]) RequiredSignaturesSatisfied [(SignatureEnvelope Bls12_381MinPk public-key-1 signature-1)] (Cluster uranus) 110 None)",
    );
    round_trip(
        CriomeReply::AuthorizationDenied(AuthorizationDenied {
            request_slot: authorization_request_slot(),
            denial: AuthorizationDenial {
                source: AuthorizationDenialSource::Policy,
                reason: AuthorizationDenialReason::SignatureScopeMismatch,
            },
        }),
        "(AuthorizationDenied authorization-request-1 (AuthorizationDenial Policy SignatureScopeMismatch))",
    );
    round_trip(
        CriomeReply::AuthorizationExpired(AuthorizationExpired {
            request_slot: authorization_request_slot(),
            expired_at: TimestampNanos::new(111),
        }),
        "(AuthorizationExpired authorization-request-1 111)",
    );
    round_trip(
        CriomeReply::AuthorizationUnavailable(AuthorizationUnavailable {
            request_slot: authorization_request_slot(),
            reason: PrincipalName::new("criome-peer-unreachable"),
        }),
        "(AuthorizationUnavailable authorization-request-1 criome-peer-unreachable)",
    );
    round_trip(
        CriomeReply::AuthorizationObservationSnapshot(AuthorizationObservationSnapshot {
            states: vec![authorization_state()],
        }),
        "(AuthorizationObservationSnapshot [(AuthorizationStateRecord authorization-request-1 digest-lojix-request Pending [(Developer reviewer)] None None)])",
    );
    round_trip(
        CriomeReply::SignatureRouteReceipt(SignatureRouteReceipt {
            request_slot: authorization_request_slot(),
            routed_to: Identity::Host(PrincipalName::new("balboa")),
        }),
        "(SignatureRouteReceipt authorization-request-1 (Host balboa))",
    );
    round_trip(
        CriomeReply::SignatureSubmissionReceipt(SignatureSubmissionReceipt {
            request_slot: authorization_request_slot(),
            signer: Identity::Developer(PrincipalName::new("reviewer")),
        }),
        "(SignatureSubmissionReceipt authorization-request-1 (Developer reviewer))",
    );
    round_trip(
        CriomeReply::AuthorizationObservationRetracted(AuthorizationObservationRetracted {
            token: authorization_observation_token(),
        }),
        "(AuthorizationObservationRetracted (AuthorizationObservationToken authorization-request-1))",
    );
    round_trip(
        CriomeReply::SubscriptionRetracted(SubscriptionRetracted { token: token() }),
        "(SubscriptionRetracted (IdentitySubscriptionToken (Persona alice)))",
    );
    round_trip(
        CriomeReply::Rejection(Rejection {
            reason: RejectionReason::UnknownIdentity,
        }),
        "(Rejection UnknownIdentity)",
    );
}

#[test]
fn canonical_event_examples_round_trip() {
    round_trip(
        CriomeEvent::IdentityUpdate(IdentityUpdate {
            receipt: IdentityReceipt {
                identity: alice(),
                status: PrincipalStatus::Active,
            },
        }),
        "(IdentityUpdate (IdentityReceipt (Persona alice) Active))",
    );
    round_trip(
        CriomeEvent::AuthorizationUpdate(AuthorizationUpdate {
            state: authorization_state(),
        }),
        "(AuthorizationUpdate (AuthorizationStateRecord authorization-request-1 digest-lojix-request Pending [(Developer reviewer)] None None))",
    );
}
