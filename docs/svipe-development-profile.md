# Svipe development proofing profile

The issuer exposes `dev.svipe.pid.sd-jwt` as a deliberately non-production
credential configuration. It is intended to exercise PID issuance using an
OIDC identity proof from Svipe while direct NFC/App Clip proofing is developed.

The typed adapter in `rust/issuer-service/src/svipe.rs` requires the identity
claims needed by the development PID and a portrait plus
`validation_portrait_present=true`. It marks normalized evidence with
`source=svipe_oidc` and `development_only=true`.

This profile is not an authoritative PID profile: it uses a development VCT,
must not be advertised as an EUDI PID, and must not be used as production
identity evidence. The eventual App Clip NFC adapter should emit the same
`IdentityEvidence` boundary, allowing the issuance and holder-binding paths to
remain unchanged.
