# 2.1.0 — first protos 0.33 text-cohort adoption

The authored Ethos, Signal implementation, examples and build script are
unchanged. Generated aliases become tuple newtypes with explicit wrapper
construction in tests. This is a wire-contract crate, not a storage engine.

Selected graph: datom-codec eabead4 (0.33.0), protos 3c7ade3 (0.33.0),
signal 7afb68b (10.3.0), ethos-zero 5a5daca (19.2.0).

Historical baseline: 5bfa61b59503a26622dea6c73f3131a0a30d4dba, version 2.0.0.
A git archive of that commit runs with its own manifest, lock, generated
source and codec. The candidate copy runs its own selected cohort. Both
scratch copies add only test-witness instrumentation. Evidence is under
`/tmp/01e4a4-runtime/`: `criome-{old,new}/tests/contract.rs`, witness and
cross-read logs with `.exit` files, and `criome-{old,new}.tsv`.

All existing canonical values are sampled: eight of the 31 Query variants
and four of the 33 Response variants. These 12 raw rkyv archives and the
existing Signal frame bytes are identical between versions; every frame
restores locally. Both cohorts also restore the other's archives and parse
the other's printed text to the same typed values. Raw text matches on only
three of 12 fixtures. A separate token-sequence inspection of both raw
outputs preserves every token and exact balanced string content: the nine
observed differences are whitespace layout only. The fixture-file assertions now explicitly compare
`compact()` output, keeping the existing one-line canonical examples while
the normal printer uses vertical layout. This normalization is not a claim
of raw text equality. The existing malformed-archive refusal is retained.

This evidence is representative, not exhaustive over every variant,
payload, rejection input, storage consumer or running deployment.
