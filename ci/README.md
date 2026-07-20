# CI proof and conformance gates

This directory is intentionally tool-neutral. Convert the gate order in `FORMAL_SPEC.md` into the selected CI system only after exact versions are pinned.

A release job must use clean, hermetic builders and archive every proof/test report. It must reject:

- blank standards digests or mutable-only source references;
- `production_ready = false`;
- incomplete requirement rows;
- Lean `sorry` or unapproved axioms;
- unproved required Tamarin lemmas;
- a Rust function that can influence `SignCredential` without refinement coverage;
- advertised profile combinations not represented by one compatibility-profile record;
- a failed OIDF/EUDI conformance case;
- unreconciled fuzz/Kani/Verus failures;
- binary/profile/configuration digests not matching the assurance bundle.
