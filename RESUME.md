# Resume note — 2026-07-27

## Completed

- Development-only Svipe proofing profile added as `dev.svipe.pid.sd-jwt`.
- Typed Svipe claim normalization requires the development identity fields,
  JPEG/JPEG2000 portrait, `validation_portrait_present=true`, and both
  `document_present` plus `face_present:iproov:gpa` assurance contexts.
- Svipe discovery is pinned to
  `https://api.svipe.com/oidc/v1/.well-known/openid-configuration` and checks
  the returned issuer.
- OIDF local-suite setup is in the EUWallet repository; the EUWallet setup was
  merged to its `main` branch.

## Not yet implemented

- Svipe Authorization Code + PKCE start/callback routes.
- Signed ID-token/JWKS validation and live Svipe claim ingestion.
- Lovable “issue development PID with Svipe” UI entry.
- Direct NFC/App Clip proofing.
- Live deployment of the Svipe path. Do not advertise the development profile
  as an authoritative PID.

## Verification

The issuer-service unit tests and clippy checks passed for the Svipe profile.
The active implementation branch was `agent/add-eudi-issuer-files`; it is
merged into `main` by the follow-up merge commit.
