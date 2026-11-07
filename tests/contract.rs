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
    PrincipalName, PublicKeyFingerprint, Query, Rejection, RejectionReason, ReplayNonce,
    RequiredSignatureThreshold, Response, Restorable, Rule, SignReceipt, SignRequest, Signal,
    Signalizable, SignatureEnvelope, SignatureScheme, SignatureSolicitation,
    SignatureSolicitationRoute, TimeSignature, TimeWindow, TimestampNanos,
};

const PRINCIPAL: &str = "criome";

fn envelope() -> SignatureEnvelope {
    SignatureEnvelope {
        signature_scheme: SignatureScheme::Bls12_381MinSig,
        bls_public_key: BlsPublicKey("b0b1".to_string()),
        bls_signature: BlsSignature("51g1".to_string()),
    }
}

fn audit_context() -> AuditContext {
    AuditContext {
        content_purpose: ContentPurpose::Authorization,
        first_principal_name: PrincipalName(PRINCIPAL.to_string()),
        second_principal_name: PrincipalName("persona".to_string()),
        replay_nonce: ReplayNonce("nonce-1".to_string()),
    }
}

fn content_reference() -> ContentReference {
    ContentReference {
        object_digest: ObjectDigest("d1ge57".to_string()),
        content_purpose: ContentPurpose::SignedObject,
        principal_name: PrincipalName(PRINCIPAL.to_string()),
    }
}

fn attestation() -> Attestation {
    Attestation {
        content_reference: content_reference(),
        identity: Identity::Persona(PrincipalName("persona".to_string())),
        signature_envelope: envelope(),
        timestamp_nanos: TimestampNanos(1_700_000_000_000_000_000),
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
            authorization_request_slot: AuthorizationRequestSlot("slot-1".to_string()),
        }),
        Query::RegisterIdentity(IdentityRegistration {
            identity: Identity::Host(PrincipalName("prometheus".to_string())),
            bls_public_key: BlsPublicKey("b0b1".to_string()),
            public_key_fingerprint: PublicKeyFingerprint("f1n93r".to_string()),
            key_purpose: KeyPurpose::HostPublication,
            signature_envelope_option: Some(envelope()),
        }),
        Query::Sign(SignRequest {
            content_reference: content_reference(),
            identity: Identity::Agent(PrincipalName("agent".to_string())),
            audit_context: audit_context(),
            timestamp_nanos_option: Some(TimestampNanos(1_700_000_000_000_000_001)),
        }),
        Query::ScheduleContractTimeCheck(ContractTimeCheck {
            contract_digest: ContractDigest(ObjectDigest("c0117ac7".to_string())),
            timestamp_nanos: TimestampNanos(1_700_000_000_000_000_003),
            authorized_object_reference: AuthorizedObjectReference {
                component_kind: ComponentKind::Criome,
                object_digest: ObjectDigest("d1ge57".to_string()),
                authorized_object_kind: AuthorizedObjectKind::Contract,
            },
            authorized_object_interest: AuthorizedObjectInterest::ObjectKind(
                AuthorizedObjectKind::Head,
            ),
        }),
        Query::AdmitContract(Contract {
            rule: Rule::SignedBy(Identity::Host(PrincipalName("prometheus".to_string()))),
            contract_parent: ContractParent::Parent(ContractDigest(ObjectDigest(
                "c0117ac7".to_string(),
            ))),
        }),
        Query::RouteSignatureRequest(SignatureSolicitationRoute {
            signature_solicitation: SignatureSolicitation {
                authorization_request_slot: AuthorizationRequestSlot("slot-1".to_string()),
                object_digest: ObjectDigest("d1ge57".to_string()),
                contract_name: ContractName("root".to_string()),
                contract_operation_head: ContractOperationHead("admit".to_string()),
                authorization_scope: AuthorizationScope("archive and release, once".to_string()),
                first_identity: Identity::Persona(PrincipalName("persona".to_string())),
                second_identity: Identity::Cluster(PrincipalName("cluster".to_string())),
            },
            identity: Identity::Agent(PrincipalName("agent".to_string())),
        }),
        Query::RunDueContractChecks(AttestedMoment {
            attested_moment_proposition: AttestedMomentProposition {
                time_window: TimeWindow {
                    first_timestamp_nanos: TimestampNanos(1_700_000_000_000_000_000),
                    second_timestamp_nanos: TimestampNanos(1_700_000_060_000_000_000),
                },
                required_signature_threshold: RequiredSignatureThreshold(2),
                identity_vector: vec![
                    Identity::Cluster(PrincipalName("cluster".to_string())),
                    Identity::Developer(PrincipalName("developer".to_string())),
                ],
            },
            time_signature_vector: vec![TimeSignature {
                identity: Identity::Cluster(PrincipalName("cluster".to_string())),
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
            timestamp_nanos: TimestampNanos(1_700_000_000_000_000_002),
        }),
        Response::Attested(AttestationReceipt {
            attestation: attestation(),
        }),
        Response::Denied(signal_criome::AuthorizationDenied {
            authorization_request_slot: AuthorizationRequestSlot("slot-1".to_string()),
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
    use protos::{Compactable, Protosizable, ReaderBudget};
    use signal_criome::{Query, Response};

    const CANONICAL: &str = include_str!("../examples/canonical.datom");

    fn budget() -> Budget {
        Budget {
            remaining: 1 << 20,
            reader: ReaderBudget::try_from(1 << 20).expect("bounded reader budget"),
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
            out.push_str(&query.datomize(vec![]).protosize().compact());
            out.push('\n');
        }
        for response in canonical_responses() {
            out.push_str(&response.datomize(vec![]).protosize().compact());
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
            written.push(query.datomize(vec![]).protosize().compact());
        }
        for response in canonical_responses() {
            written.push(response.datomize(vec![]).protosize().compact());
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
                    assert_eq!(query.datomize(vec![]).protosize().compact(), line)
                }
                (None, Some(response)) => {
                    assert_eq!(response.datomize(vec![]).protosize().compact(), line)
                }
                (Some(_), Some(_)) => panic!("ambiguous canonical line: {line}"),
                (None, None) => panic!("unreadable canonical line: {line}"),
            }
        }
    }
}
