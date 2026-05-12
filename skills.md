# signal-criome skill

Work here when the change concerns Criome trust and attestation contract
records.

Rules for work here:

- Keep this crate as pure Signal contract vocabulary.
- Do not add daemon code, sockets, actors, tokio runtime code, redb tables, or
  Sema storage here.
- Use BLS-only signature scheme vocabulary for Spartan Criome.
- Do not introduce `AuthProof`; use specific nouns such as
  `SignatureEnvelope`, `Attestation`, `VerificationResult`, and
  `DelegationGrant`.
- Keep attestations out-of-band from Persona content records.
