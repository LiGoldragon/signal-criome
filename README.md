# signal-criome

Signal contract vocabulary for Criome's Spartan BLS trust and attestation
substrate.

This crate defines the typed records crossing the Criome daemon boundary. The
daemon verifies and records cryptographic authority; Persona decides and acts.


## Current-Criome compatibility line

Version 0.11.1 pins the established legacy Nota, Signal Frame, and
schema-generator family without changing this contract schema or generated wire
artifacts. It exists so Orchestrate maintenance can use the current Criome
0.11 contract family while the Protos migration remains pending.
