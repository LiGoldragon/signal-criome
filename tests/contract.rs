//! The contract's own witness: every canonical value survives the wire, and
//! every canonical Datom line is the codec's own text for one of them.
//!
//! Every name is taken from `signal_criome` alone — the frame and the shared
//! taxonomy included. A consumer speaks this contract without naming `signal`
//! itself, and the frame it gets is `signal`'s own type, not a copy.

use signal_criome::{
    Attestation, AttestationReceipt, AttestedMoment, AttestedMomentProposition, AuditContext,
    AuthorizationDenial, AuthorizationDenialReason, AuthorizationDenialSource,
    AuthorizationObservation, AuthorizationRequestSlot, AuthorizationScope,
    AuthorizedObjectInterest, AuthorizedObjectKind, AuthorizedObjectReference, BlsPublicKey,
    BlsSignature, ByteViewable, ComponentKind, ContentPurpose, ContentReference, Contract,
    ContractDigest, ContractName, ContractOperationHead, ContractParent, ContractTimeCheck,
    Identity, IdentityRegistration, KeyPurpose, ObjectDigest, ParkedAuthorizationObservation,
    PrincipalName, PublicKeyFingerprint, Query, Rejection, RejectionReason, ReplayNonce, Response,
    Restorable, Rule, SignReceipt, SignRequest, Signal, Signalizable, SignatureEnvelope,
    SignatureScheme, SignatureSolicitation, SignatureSolicitationRoute, TimeSignature, TimeWindow,
    TimestampNanos,
};

const PRINCIPAL: &str = "criome";

fn envelope() -> SignatureEnvelope {
    SignatureEnvelope {
        signature_scheme: SignatureScheme::Bls12_381MinSig,
        bls_public_key: BlsPublicKey::from("b0b1"),
        bls_signature: BlsSignature::from("51g1"),
    }
}

fn audit_context() -> AuditContext {
    AuditContext {
        content_purpose: ContentPurpose::Authorization,
        first_principal_name: PrincipalName::from(PRINCIPAL),
        second_principal_name: PrincipalName::from("persona"),
        replay_nonce: ReplayNonce::from("nonce-1"),
    }
}

fn content_reference() -> ContentReference {
    ContentReference {
        object_digest: ObjectDigest::from("d1ge57"),
        content_purpose: ContentPurpose::SignedObject,
        principal_name: PrincipalName::from(PRINCIPAL),
    }
}

fn attestation() -> Attestation {
    Attestation {
        content_reference: content_reference(),
        identity: Identity::Persona(PrincipalName::from("persona")),
        signature_envelope: envelope(),
        timestamp_nanos: 1_700_000_000_000_000_000,
        timestamp_nanos_option: None,
        audit_context: audit_context(),
    }
}

/// Every canonical request. Each exercises a shape the projection must hold:
/// an empty struct, a `Some` and a `None` option, a vector, a nested enum, a
/// struct with two positions of one type, and an imported taxonomy name.
fn canonical_queries() -> Vec<Query> {
    vec![
        Query::ObserveParkedAuthorizations(ParkedAuthorizationObservation {}),
        Query::ObserveAuthorization(AuthorizationObservation {
            authorization_request_slot: AuthorizationRequestSlot::from("slot-1"),
        }),
        Query::RegisterIdentity(IdentityRegistration {
            identity: Identity::Host(PrincipalName::from("prometheus")),
            bls_public_key: BlsPublicKey::from("b0b1"),
            public_key_fingerprint: PublicKeyFingerprint::from("f1n93r"),
            key_purpose: KeyPurpose::HostPublication,
            signature_envelope_option: Some(envelope()),
        }),
        Query::Sign(SignRequest {
            content_reference: content_reference(),
            identity: Identity::Agent(PrincipalName::from("agent")),
            audit_context: audit_context(),
            timestamp_nanos_option: Some(TimestampNanos::from(1_700_000_000_000_000_001i64)),
        }),
        Query::ScheduleContractTimeCheck(ContractTimeCheck {
            contract_digest: ContractDigest::from("c0117ac7"),
            timestamp_nanos: 1_700_000_000_000_000_003,
            authorized_object_reference: AuthorizedObjectReference {
                component_kind: ComponentKind::Criome,
                object_digest: ObjectDigest::from("d1ge57"),
                authorized_object_kind: AuthorizedObjectKind::Contract,
            },
            authorized_object_interest: AuthorizedObjectInterest::ObjectKind(
                AuthorizedObjectKind::Head,
            ),
        }),
        Query::AdmitContract(Contract {
            rule: Rule::SignedBy(Identity::Host(PrincipalName::from("prometheus"))),
            contract_parent: ContractParent::Parent(ContractDigest::from("c0117ac7")),
        }),
        Query::RouteSignatureRequest(SignatureSolicitationRoute {
            signature_solicitation: SignatureSolicitation {
                authorization_request_slot: AuthorizationRequestSlot::from("slot-1"),
                object_digest: ObjectDigest::from("d1ge57"),
                contract_name: ContractName::from("root"),
                contract_operation_head: ContractOperationHead::from("admit"),
                authorization_scope: AuthorizationScope::from("archive and release, once"),
                first_identity: Identity::Persona(PrincipalName::from("persona")),
                second_identity: Identity::Cluster(PrincipalName::from("cluster")),
            },
            identity: Identity::Agent(PrincipalName::from("agent")),
        }),
        Query::RunDueContractChecks(AttestedMoment {
            attested_moment_proposition: AttestedMomentProposition {
                time_window: TimeWindow {
                    first_timestamp_nanos: 1_700_000_000_000_000_000,
                    second_timestamp_nanos: 1_700_000_060_000_000_000,
                },
                required_signature_threshold: 2,
                identity_vector: vec![
                    Identity::Cluster(PrincipalName::from("cluster")),
                    Identity::Developer(PrincipalName::from("developer")),
                ],
            },
            time_signature_vector: vec![TimeSignature {
                identity: Identity::Cluster(PrincipalName::from("cluster")),
                signature_envelope: envelope(),
            }],
        }),
    ]
}

/// Every canonical reply.
fn canonical_responses() -> Vec<Response> {
    vec![
        Response::Refused(Rejection {
            rejection_reason: RejectionReason::ReplayAttempted,
        }),
        Response::Signed(SignReceipt {
            attestation: attestation(),
            timestamp_nanos: 1_700_000_000_000_000_002,
        }),
        Response::Attested(AttestationReceipt {
            attestation: attestation(),
        }),
        Response::Denied(signal_criome::AuthorizationDenied {
            authorization_request_slot: AuthorizationRequestSlot::from("slot-1"),
            authorization_denial: AuthorizationDenial {
                authorization_denial_source: AuthorizationDenialSource::Policy,
                authorization_denial_reason: AuthorizationDenialReason::PolicyRefused,
            },
        }),
    ]
}

#[test]
fn every_canonical_query_restores_from_fresh_peer_bytes() {
    for query in canonical_queries() {
        let received = Signal::<Query>::from(query.signalize().expect("archive").bytes().to_vec());
        assert_eq!(received.restore().expect("restore"), query);
    }
}

#[test]
fn every_canonical_response_restores_from_fresh_peer_bytes() {
    for response in canonical_responses() {
        let received =
            Signal::<Response>::from(response.signalize().expect("archive").bytes().to_vec());
        assert_eq!(received.restore().expect("restore"), response);
    }
}

#[test]
fn a_malformed_archive_is_refused() {
    assert!(Signal::<Query>::from(vec![1, 2, 3]).restore().is_err());
    assert!(Signal::<Response>::from(vec![1, 2, 3]).restore().is_err());
}

#[cfg(feature = "datom")]
mod canonical {
    use super::{canonical_queries, canonical_responses};
    use datom_codec::{Actualizing, Budget, Datomizable, Potential};
    use protos::{Protosizable, ReaderBudget, Textualizable};
    use signal_criome::{Query, Response};

    const CANONICAL: &str = include_str!("../examples/canonical.datom");

    fn budget() -> Budget {
        Budget {
            remaining: 1 << 20,
            reader: ReaderBudget { remaining: 1 << 20 },
            depth: 0,
            maximum_depth: 256,
        }
    }

    fn lines() -> Vec<String> {
        CANONICAL
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with(';'))
            .map(str::to_string)
            .collect()
    }

    /// Rewrite `examples/canonical.datom` from the canonical values. The file
    /// is the codec's product, never text spelled by hand; run this whenever
    /// the canonical values change:
    ///
    /// ```text
    /// cargo test --features datom -- --ignored rewrite_the_canonical_file
    /// ```
    #[test]
    #[ignore = "writes the source tree; run deliberately when the values change"]
    fn rewrite_the_canonical_file() {
        let mut out = String::from("; Canonical Datom examples for signal-criome.\n");
        out.push_str("; Written by `rewrite_the_canonical_file`; never spelled by hand.\n\n");
        for query in canonical_queries() {
            out.push_str(&query.datomize(vec![]).protosize().textualize());
            out.push('\n');
        }
        for response in canonical_responses() {
            out.push_str(&response.datomize(vec![]).protosize().textualize());
            out.push('\n');
        }
        std::fs::write(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/canonical.datom"),
            out,
        )
        .expect("write canonical");
    }

    /// The canonical file is the codec's own text for the canonical values —
    /// never text spelled by hand.
    #[test]
    fn the_canonical_file_is_what_the_codec_writes() {
        let mut written: Vec<String> = Vec::new();
        for query in canonical_queries() {
            written.push(query.datomize(vec![]).protosize().textualize());
        }
        for response in canonical_responses() {
            written.push(response.datomize(vec![]).protosize().textualize());
        }
        assert_eq!(lines(), written);
    }

    /// Every line the file carries actualizes — as a request or as a reply,
    /// never as neither and never as both.
    #[test]
    fn every_canonical_line_actualizes_into_exactly_one_root() {
        let lines = lines();
        assert!(!lines.is_empty());
        for line in lines {
            let query = Potential::<Query>::from(line.clone())
                .actualize(&mut budget())
                .ok();
            let response = Potential::<Response>::from(line.clone())
                .actualize(&mut budget())
                .ok();
            match (query, response) {
                (Some(query), None) => {
                    assert_eq!(query.datomize(vec![]).protosize().textualize(), line)
                }
                (None, Some(response)) => {
                    assert_eq!(response.datomize(vec![]).protosize().textualize(), line)
                }
                (Some(_), Some(_)) => panic!("ambiguous canonical line: {line}"),
                (None, None) => panic!("unreadable canonical line: {line}"),
            }
        }
    }
}
