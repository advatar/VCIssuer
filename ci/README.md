# CI proof and conformance gates

GitHub Actions implements the currently executable gates in
`.github/workflows/verify.yml`: Rust formatting, default and Keychain tests,
clippy, Lean compilation, Tamarin proofs, and bundle checksum verification.
The workflow pins Rust and Bun directly and installs the 1.12 Tamarin formula.
External conformance and certification evidence remains a release gate rather
than something CI can manufacture.

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
