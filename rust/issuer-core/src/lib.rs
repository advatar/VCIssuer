#![forbid(unsafe_code)]
//! Minimal pure decision kernel mirroring the Lean seed model.
//!
//! Production code must replace Boolean evidence flags with structured,
//! provenance-carrying evidence values and link every signing-influencing
//! function to a Lean refinement theorem.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instant(pub u64);

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u128);
    };
}

id_type!(SessionId);
id_type!(RequestId);
id_type!(ProfileId);
id_type!(SubjectId);
id_type!(DatasetId);
id_type!(KeyThumbprint);
id_type!(NonceId);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssuerRole {
    Pid,
    Qeaa,
    PublicBodyEaa,
    NonQualifiedEaa,
    DevelopmentEvidence,
    /// Power-of-representation / mandate attestation (ARF Topic 29): a delegator grants a delegate
    /// (which MAY be an AI agent) a scoped, revocable authority. Issuance is gated on a proven
    /// delegator, the delegate key the mandate binds, and monotonic power narrowing.
    Representation,
}

/// A bounded set of authorized operations, one bit per operation. Using a bitmask keeps the
/// scope-containment relation (`powers_subset`) a decidable `const fn` that the Lean model can
/// mirror exactly — the delegate can never be granted a power the delegator did not hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Powers(pub u64);

impl Powers {
    /// Every set bit in `self` is also set in `grant` — i.e. `self ⊆ grant` (monotonic narrowing).
    /// Mirrors the Lean `Powers.subsetOf` (`Nat.land a b = a`).
    #[must_use]
    pub const fn subset_of(self, grant: Powers) -> bool {
        (self.0 & grant.0) == self.0
    }
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// The pinned power-of-representation mandate credential type (SD-JWT VC `vct`), per the delegation
/// design brief. A distinct attestation type (ARF Topic 29) whose holder is the delegate agent.
pub const MANDATE_VCT: &str = "urn:eudi:mandate:1";

/// Canonical, pinned power → scope-URN taxonomy: each entry maps ONE power bit to a stable scope
/// URN. This is the single source of truth for the mandate scope model — the issuer serialises
/// `granted_powers` to these URNs and the verifier checks `requested ⊆ granted` over the URN set.
/// Because the map is one-bit ↔ one-URN and injective, scope-set containment agrees exactly with
/// [`Powers::subset_of`] over taxonomy-covered powers (proved by `taxonomy_bridges_subset` below),
/// which is what makes the verifier's decidable subset relation sound.
pub const POWER_TAXONOMY: [(u32, &str); 6] = [
    (0, "urn:eudi:mandate:power:present-identity"),
    (1, "urn:eudi:mandate:power:sign-document"),
    (2, "urn:eudi:mandate:power:authorise-payment"),
    (3, "urn:eudi:mandate:power:manage-subscription"),
    (4, "urn:eudi:mandate:power:access-records"),
    (5, "urn:eudi:mandate:power:administer-account"),
];

/// Bitmask of every bit assigned a scope URN in [`POWER_TAXONOMY`]. A mandate's requested powers
/// must lie within this mask to be expressible on the wire.
pub const TAXONOMY_MASK: u64 = {
    let mut mask = 0u64;
    let mut i = 0;
    while i < POWER_TAXONOMY.len() {
        mask |= 1u64 << POWER_TAXONOMY[i].0;
        i += 1;
    }
    mask
};

/// Serialise a `Powers` bitmask to its canonical, taxonomy-ordered scope URNs. Bits with no entry
/// in [`POWER_TAXONOMY`] are dropped (they are not expressible as a wire scope).
#[must_use]
pub fn powers_to_scope_urns(powers: Powers) -> Vec<&'static str> {
    POWER_TAXONOMY
        .iter()
        .filter(|(bit, _)| powers.0 & (1u64 << bit) != 0)
        .map(|(_, urn)| *urn)
        .collect()
}

/// The verifier's decidable scope-containment relation: every requested scope URN is present in the
/// granted set. Mirrored 1:1 on the VCVerifier side; over [`POWER_TAXONOMY`] it agrees with
/// [`Powers::subset_of`].
#[must_use]
pub fn scope_urns_subset(requested: &[&str], granted: &[&str]) -> bool {
    requested.iter().all(|urn| granted.contains(urn))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialFormat {
    SdJwtVc,
    Mdoc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialProfile {
    pub id: ProfileId,
    pub role: IssuerRole,
    pub format: CredentialFormat,
    pub enabled: bool,
    pub device_binding_required: bool,
    pub pid_binding_required: bool,
    /// When set, issuance is gated on isolated hybrid-PQ evidence (`Session::hybrid_pq_bound`),
    /// downgrade-closed — the PQ *capability*: a profile that sets it can never be issued on
    /// classical-only evidence (proven by `may_issue`). The current SD-JWT mandate service path
    /// signs ES256 and leaves this unset, so a post-quantum mandate is a profiled option (route
    /// through the hybrid signer), not yet the default.
    pub require_hybrid_pq: bool,
    /// When set, issuance is gated on structured eMRTD chip + liveness evidence
    /// (`Session::chip_evidence`), downgrade-closed exactly like `require_hybrid_pq`: a profile that
    /// sets it (the NFC-sourced PID profile) can never be issued without a chip read whose Passive
    /// Authentication verified against a trusted CSCA, whose anti-cloning proof held, and whose
    /// holder liveness matched the chip portrait (proven by `may_issue`). PID profiles that proof
    /// the subject some other way leave it unset and are unaffected.
    pub require_chip_liveness: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub valid_from: Instant,
    pub valid_until: Instant,
    pub fresh_until: Instant,
    pub accepted: bool,
}

impl Evidence {
    #[must_use]
    pub const fn usable_at(self, now: Instant) -> bool {
        self.accepted
            && self.valid_from.0 <= now.0
            && now.0 < self.valid_until.0
            && now.0 <= self.fresh_until.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub evidence: Evidence,
    pub profile: ProfileId,
    pub subject: SubjectId,
    pub dataset: DatasetId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenBinding {
    pub evidence: Evidence,
    pub dpop_key: KeyThumbprint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialProof {
    pub evidence: Evidence,
    pub nonce: NonceId,
    pub holder_key: KeyThumbprint,
    pub possession_valid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletEvidence {
    pub wia: Evidence,
    pub ka: Option<Evidence>,
    pub wallet_not_revoked: bool,
    pub holder_key_approved: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubjectEvidence {
    pub evidence: Evidence,
    pub subject: SubjectId,
    pub loa_high: bool,
    pub entitled: bool,
    pub claims_current: bool,
    pub dataset: DatasetId,
    pub pid_binding_verified: bool,
}

/// Delegation context for a power-of-representation issuance. The delegator is authenticated by
/// their own presented attestation (PID for a natural person; LPID + signatory-rights for a legal
/// person) carried as `delegator_evidence` + `delegator`; `grant` is the authority the delegator
/// actually holds; `delegate_key` is the key the resulting mandate is bound to — the AI agent's
/// holder key. `mandate_not_revoked` reflects the delegator's live grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delegation {
    pub delegator_evidence: Evidence,
    pub delegator: SubjectId,
    pub delegate_key: KeyThumbprint,
    pub grant: Powers,
    pub mandate_not_revoked: bool,
}

/// Structured evidence from an in-wallet eMRTD (ICAO 9303 passport / national eID) chip read,
/// carried when issuing an NFC-sourced PID. Every boolean is a *verified verdict the issuer itself
/// reproduced* over the raw data groups + EF.SOD delivered by the reader (HPKE-encrypted to the
/// issuer), not a self-asserted flag from the wallet:
///
/// - `sod_passive_auth`: Passive Authentication succeeded — the EF.SOD CMS signature is valid, its
///   Document Signer certificate chains to a CSCA in the issuer's own trust store, and every read
///   data group's hash matches the LDS Security Object. This is what binds DG1 (MRZ) and DG2
///   (portrait) to a genuine, unmodified chip.
/// - `chip_authentic`: an anti-cloning proof held — Chip/Active Authentication or PACE-CAM — so the
///   chip is the original, not a copied datagroup dump.
/// - `liveness_matched`: a *fresh* holder liveness capture matched the DG2 portrait, binding the
///   person presenting the wallet to the document that was read.
///
/// `subject` is the identity the read establishes; it must equal the request subject so the minted
/// PID cannot be pointed at a different holder. `evidence` carries the read's validity/freshness
/// window (a stale read is refused via `usable_at`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChipLivenessEvidence {
    pub evidence: Evidence,
    pub subject: SubjectId,
    pub sod_passive_auth: bool,
    pub chip_authentic: bool,
    pub liveness_matched: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub id: RequestId,
    pub profile: ProfileId,
    pub subject: SubjectId,
    pub dataset: DatasetId,
    pub dpop_key: KeyThumbprint,
    pub proof: CredentialProof,
    pub expiry: Instant,
    /// Powers the mandate would authorize. Ignored unless the profile role is `Representation`;
    /// must be a non-empty subset of the delegator's `grant`.
    pub requested_powers: Powers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: SessionId,
    pub profile: CredentialProfile,
    pub authorization: Authorization,
    pub token: TokenBinding,
    pub wallet: WalletEvidence,
    pub subject: SubjectEvidence,
    pub expected_nonce: NonceId,
    pub nonce_unused: bool,
    pub issuer_entitled: bool,
    pub status_reserved: bool,
    pub already_issued: bool,
    pub wia_ka_maintenance_end: Instant,
    /// Isolated hybrid-PQ evidence is present and accepted for this session (downgrade-closed).
    pub hybrid_pq_bound: bool,
    /// Present iff the profile role is `Representation`; carries the authenticated delegator, the
    /// delegate (agent) key, and the delegator's live grant.
    pub delegation: Option<Delegation>,
    /// Present when the issuer verified an eMRTD chip read + holder liveness for this session
    /// (the NFC-sourced PID flow). Required — and checked — iff `profile.require_chip_liveness`.
    pub chip_evidence: Option<ChipLivenessEvidence>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignCommand {
    pub session: SessionId,
    pub request: RequestId,
    pub profile: ProfileId,
    pub subject: SubjectId,
    pub holder_key: KeyThumbprint,
    /// For a `Representation` mandate: the authenticated delegator the mandate acts on behalf of,
    /// and the exact powers granted (already narrowed to a subset of the delegator's grant). `None`
    /// / empty for a non-delegation issuance.
    pub on_behalf_of: Option<SubjectId>,
    pub granted_powers: Powers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionError {
    NotAuthorized,
}

#[must_use]
pub const fn role_evidence_ok(role: IssuerRole, subject: SubjectEvidence) -> bool {
    match role {
        IssuerRole::Pid => subject.loa_high,
        IssuerRole::Qeaa
        | IssuerRole::PublicBodyEaa
        | IssuerRole::NonQualifiedEaa
        | IssuerRole::DevelopmentEvidence
        // Representation gates on the delegator + delegate + scope in `representation_ok`, not on
        // the mandate subject's own LoA.
        | IssuerRole::Representation => true,
    }
}

/// Delegation gate for power-of-representation issuance. For any non-`Representation` role this is
/// vacuously true. For `Representation` it requires: an authenticated, live delegator; a mandate
/// bound to the delegate (agent) key that proved possession; and a NON-EMPTY set of requested
/// powers that is a SUBSET of the delegator's own grant (monotonic narrowing — a delegate can never
/// be granted authority the delegator did not hold).
#[must_use]
pub const fn representation_ok(session: Session, request: Request, now: Instant) -> bool {
    match session.profile.role {
        IssuerRole::Representation => match session.delegation {
            Some(d) => {
                d.delegator_evidence.usable_at(now)
                    && d.mandate_not_revoked
                    && d.delegate_key.0 == request.proof.holder_key.0
                    && !request.requested_powers.is_empty()
                    && request.requested_powers.subset_of(d.grant)
            }
            None => false,
        },
        _ => true,
    }
}

/// Chip + liveness gate for an NFC-sourced PID issuance. Downgrade-closed like the hybrid-PQ gate:
/// the `may_issue` conjunct only *invokes* this when `profile.require_chip_liveness` is set, and
/// then it demands a chip-read evidence value that is fresh, Passive-Authenticated against a
/// trusted CSCA, anti-clone proven, liveness-matched, and bound to the request subject. A profile
/// that does not require chip liveness short-circuits before reaching here (vacuously satisfied).
/// A required profile with no `chip_evidence` fails closed.
#[must_use]
pub const fn chip_liveness_ok(session: Session, request: Request, now: Instant) -> bool {
    match session.chip_evidence {
        Some(e) => {
            e.evidence.usable_at(now)
                && e.sod_passive_auth
                && e.chip_authentic
                && e.liveness_matched
                && e.subject.0 == request.subject.0
        }
        None => false,
    }
}

#[must_use]
pub const fn device_binding_ok(
    profile: CredentialProfile,
    wallet: WalletEvidence,
    proof: CredentialProof,
) -> bool {
    if profile.device_binding_required {
        wallet.holder_key_approved && proof.possession_valid && wallet.ka.is_some()
    } else {
        proof.possession_valid
    }
}

/// Minimal executable form of the canonical `MayIssue` predicate.
#[must_use]
pub const fn may_issue(session: Session, request: Request, now: Instant) -> bool {
    session.profile.enabled
        && session.profile.id.0 == request.profile.0
        && session.issuer_entitled
        && session.authorization.evidence.usable_at(now)
        && session.authorization.profile.0 == request.profile.0
        && session.authorization.subject.0 == request.subject.0
        && session.authorization.dataset.0 == request.dataset.0
        && session.token.evidence.usable_at(now)
        && session.token.dpop_key.0 == request.dpop_key.0
        && request.proof.evidence.usable_at(now)
        && request.proof.nonce.0 == session.expected_nonce.0
        && session.nonce_unused
        && request.proof.holder_key.0 == request.dpop_key.0
        && session.wallet.wia.usable_at(now)
        && session.wallet.wallet_not_revoked
        && device_binding_ok(session.profile, session.wallet, request.proof)
        && session.subject.evidence.usable_at(now)
        && session.subject.subject.0 == request.subject.0
        && session.subject.dataset.0 == request.dataset.0
        && session.subject.entitled
        && session.subject.claims_current
        // NOTE: this PID-binding conjunct (the delegator/PID-presentation authentication used by the
        // mandate + PID-bound-QEAA flows) is an intentional Rust-ONLY guard. The Lean `mayIssue`
        // abstracts the credential-binding + delegation decision and does NOT model the wallet's
        // PID-presentation adapter step, so the Rust↔Lean correspondence is faithful on the modelled
        // gates but is NOT a full 1:1 (Rust is strictly stricter here — fail-closed).
        && (!session.profile.pid_binding_required || session.subject.pid_binding_verified)
        && role_evidence_ok(session.profile.role, session.subject)
        && request.expiry.0 <= session.wia_ka_maintenance_end.0
        && session.status_reserved
        && !session.already_issued
        // Post-quantum: when the profile requires it (mandates do), isolated hybrid-PQ evidence
        // must be present — downgrade-closed.
        && (!session.profile.require_hybrid_pq || session.hybrid_pq_bound)
        // Delegation: monotonic-narrowing power-of-representation gate.
        && representation_ok(session, request, now)
        // NFC-sourced PID: when the profile requires it, a chip read with verified Passive
        // Authentication, anti-cloning, and portrait-matched liveness must be present —
        // downgrade-closed (a require_chip_liveness profile can never be issued without it).
        && (!session.profile.require_chip_liveness || chip_liveness_ok(session, request, now))
}

/// The sole pure gateway to a credential signing command.
pub const fn authorize_sign(
    session: Session,
    request: Request,
    now: Instant,
) -> Result<SignCommand, DecisionError> {
    if may_issue(session, request, now) {
        let (on_behalf_of, granted_powers) = match (session.profile.role, session.delegation) {
            (IssuerRole::Representation, Some(d)) => (Some(d.delegator), request.requested_powers),
            _ => (None, Powers(0)),
        };
        Ok(SignCommand {
            session: session.id,
            request: request.id,
            profile: request.profile,
            subject: request.subject,
            holder_key: request.proof.holder_key,
            on_behalf_of,
            granted_powers,
        })
    } else {
        Err(DecisionError::NotAuthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Instant = Instant(100);

    const fn valid_evidence() -> Evidence {
        Evidence {
            valid_from: Instant(1),
            valid_until: Instant(200),
            fresh_until: Instant(150),
            accepted: true,
        }
    }

    const fn fixture() -> (Session, Request) {
        let profile = CredentialProfile {
            id: ProfileId(1),
            role: IssuerRole::Pid,
            format: CredentialFormat::SdJwtVc,
            enabled: true,
            device_binding_required: true,
            pid_binding_required: false,
            require_hybrid_pq: false,
            require_chip_liveness: false,
        };
        let proof = CredentialProof {
            evidence: valid_evidence(),
            nonce: NonceId(9),
            holder_key: KeyThumbprint(7),
            possession_valid: true,
        };
        let request = Request {
            id: RequestId(3),
            profile: ProfileId(1),
            subject: SubjectId(4),
            dataset: DatasetId(5),
            dpop_key: KeyThumbprint(7),
            proof,
            expiry: Instant(140),
            requested_powers: Powers(0),
        };
        let session = Session {
            id: SessionId(2),
            profile,
            authorization: Authorization {
                evidence: valid_evidence(),
                profile: ProfileId(1),
                subject: SubjectId(4),
                dataset: DatasetId(5),
            },
            token: TokenBinding {
                evidence: valid_evidence(),
                dpop_key: KeyThumbprint(7),
            },
            wallet: WalletEvidence {
                wia: valid_evidence(),
                ka: Some(valid_evidence()),
                wallet_not_revoked: true,
                holder_key_approved: true,
            },
            subject: SubjectEvidence {
                evidence: valid_evidence(),
                subject: SubjectId(4),
                loa_high: true,
                entitled: true,
                claims_current: true,
                dataset: DatasetId(5),
                pid_binding_verified: false,
            },
            expected_nonce: NonceId(9),
            nonce_unused: true,
            issuer_entitled: true,
            status_reserved: true,
            already_issued: false,
            wia_ka_maintenance_end: Instant(160),
            hybrid_pq_bound: false,
            delegation: None,
            chip_evidence: None,
        };
        (session, request)
    }

    /// Turn the base fixture into an NFC-sourced PID issuance: the profile requires chip+liveness
    /// evidence, and the session carries a verified chip read (Passive Auth held, chip authentic,
    /// liveness matched) bound to the request subject (4). Valid by construction.
    fn nfc_pid_fixture() -> (Session, Request) {
        let (mut session, request) = fixture();
        session.profile.require_chip_liveness = true;
        session.chip_evidence = Some(ChipLivenessEvidence {
            evidence: valid_evidence(),
            subject: SubjectId(4),
            sod_passive_auth: true,
            chip_authentic: true,
            liveness_matched: true,
        });
        (session, request)
    }

    /// Turn the base fixture into a hybrid-PQ power-of-representation (mandate) issuance: the
    /// delegator holds powers 0b1110, the mandate is bound to the agent's holder key (7), and the
    /// request narrows to 0b0110 (a subset). Valid by construction.
    fn mandate_fixture() -> (Session, Request) {
        let (mut session, mut request) = fixture();
        session.profile.role = IssuerRole::Representation;
        session.profile.require_hybrid_pq = true;
        session.hybrid_pq_bound = true;
        session.delegation = Some(Delegation {
            delegator_evidence: valid_evidence(),
            delegator: SubjectId(42),
            delegate_key: KeyThumbprint(7),
            grant: Powers(0b1110),
            mandate_not_revoked: true,
        });
        request.requested_powers = Powers(0b0110);
        (session, request)
    }

    #[test]
    fn mandate_narrowing_within_grant_signs_on_behalf_of_delegator() {
        let (session, request) = mandate_fixture();
        let cmd = authorize_sign(session, request, NOW).expect("valid mandate");
        assert_eq!(cmd.on_behalf_of, Some(SubjectId(42)));
        assert_eq!(cmd.granted_powers, Powers(0b0110));
    }

    #[test]
    fn mandate_cannot_widen_beyond_delegator_grant() {
        let (session, mut request) = mandate_fixture();
        // 0b0001 is NOT in the delegator's grant 0b1110 → widening → refused.
        request.requested_powers = Powers(0b0111);
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn mandate_bound_to_wrong_delegate_key_is_refused() {
        let (mut session, request) = mandate_fixture();
        if let Some(d) = session.delegation.as_mut() {
            d.delegate_key = KeyThumbprint(8); // not the key that proved possession (7)
        }
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn revoked_mandate_is_refused() {
        let (mut session, request) = mandate_fixture();
        if let Some(d) = session.delegation.as_mut() {
            d.mandate_not_revoked = false;
        }
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn mandate_without_hybrid_pq_evidence_is_refused() {
        let (mut session, request) = mandate_fixture();
        session.hybrid_pq_bound = false; // profile requires PQ → downgrade-closed
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn mandate_with_empty_scope_is_refused() {
        let (session, mut request) = mandate_fixture();
        request.requested_powers = Powers(0);
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn representation_role_requires_a_delegation_context() {
        let (mut session, request) = mandate_fixture();
        session.delegation = None;
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn nfc_pid_with_verified_chip_and_liveness_signs() {
        let (session, request) = nfc_pid_fixture();
        let cmd = authorize_sign(session, request, NOW).expect("valid NFC-sourced PID");
        // A PID issuance carries no delegation powers.
        assert_eq!(cmd.on_behalf_of, None);
        assert_eq!(cmd.subject, SubjectId(4));
    }

    #[test]
    fn nfc_pid_without_chip_evidence_is_refused() {
        let (mut session, request) = nfc_pid_fixture();
        session.chip_evidence = None; // profile requires it → downgrade-closed
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn nfc_pid_with_failed_passive_auth_is_refused() {
        let (mut session, request) = nfc_pid_fixture();
        if let Some(e) = session.chip_evidence.as_mut() {
            e.sod_passive_auth = false; // SOD/CSCA chain or DG hashes did not verify
        }
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn nfc_pid_from_a_cloned_chip_is_refused() {
        let (mut session, request) = nfc_pid_fixture();
        if let Some(e) = session.chip_evidence.as_mut() {
            e.chip_authentic = false; // no Active/Chip Authentication / CAM anti-cloning proof
        }
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn nfc_pid_without_liveness_match_is_refused() {
        let (mut session, request) = nfc_pid_fixture();
        if let Some(e) = session.chip_evidence.as_mut() {
            e.liveness_matched = false; // holder liveness did not match the DG2 portrait
        }
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn nfc_pid_chip_evidence_for_a_different_subject_is_refused() {
        let (mut session, request) = nfc_pid_fixture();
        if let Some(e) = session.chip_evidence.as_mut() {
            e.subject = SubjectId(99); // chip established a different identity than requested
        }
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn nfc_pid_with_stale_chip_read_is_refused() {
        let (mut session, request) = nfc_pid_fixture();
        if let Some(e) = session.chip_evidence.as_mut() {
            // Read went stale before this issuance (fresh_until < now).
            e.evidence.fresh_until = Instant(50);
        }
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn chip_liveness_is_ignored_when_the_profile_does_not_require_it() {
        // The base PID fixture does not require chip liveness and has no chip evidence, yet signs:
        // the NFC gate is downgrade-closed only for profiles that opt in.
        let (session, request) = fixture();
        assert!(!session.profile.require_chip_liveness);
        assert!(session.chip_evidence.is_none());
        assert!(authorize_sign(session, request, NOW).is_ok());
    }

    #[test]
    fn authorized_fixture_can_sign() {
        let (session, request) = fixture();
        assert!(authorize_sign(session, request, NOW).is_ok());
    }

    #[test]
    fn used_nonce_cannot_sign() {
        let (mut session, request) = fixture();
        session.nonce_unused = false;
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn pid_without_loa_high_cannot_sign() {
        let (mut session, request) = fixture();
        session.subject.loa_high = false;
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn pid_bound_profile_requires_verified_cross_attestation_evidence() {
        let (mut session, request) = fixture();
        session.profile.pid_binding_required = true;
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
        session.subject.pid_binding_verified = true;
        assert!(authorize_sign(session, request, NOW).is_ok());
    }

    #[test]
    fn expired_wia_ka_maintenance_bound_cannot_sign() {
        let (session, mut request) = fixture();
        request.expiry = Instant(161);
        assert_eq!(
            authorize_sign(session, request, NOW),
            Err(DecisionError::NotAuthorized)
        );
    }

    #[test]
    fn taxonomy_mask_covers_exactly_the_taxonomy_bits() {
        let expected: u64 = POWER_TAXONOMY.iter().map(|(bit, _)| 1u64 << bit).sum();
        assert_eq!(TAXONOMY_MASK, expected);
        // Every taxonomy power is a subset of the full taxonomy mask.
        for (bit, _) in POWER_TAXONOMY {
            assert!(Powers(1u64 << bit).subset_of(Powers(TAXONOMY_MASK)));
        }
    }

    #[test]
    fn powers_to_scope_urns_is_canonical_and_drops_untaxonomised_bits() {
        // bits 0 and 1 → the first two taxonomy URNs, in taxonomy order.
        assert_eq!(
            powers_to_scope_urns(Powers(0b11)),
            vec![
                "urn:eudi:mandate:power:present-identity",
                "urn:eudi:mandate:power:sign-document",
            ]
        );
        // A bit outside the taxonomy contributes no wire scope.
        assert!(powers_to_scope_urns(Powers(1u64 << 60)).is_empty());
        assert!(powers_to_scope_urns(Powers(0)).is_empty());
    }

    #[test]
    fn taxonomy_bridges_subset_exhaustively() {
        // Over the whole taxonomy space, the wire scope-set containment relation agrees exactly
        // with the kernel's `Powers::subset_of` — this is what makes the verifier's decidable
        // URN-subset check a sound stand-in for the proven bitmask narrowing.
        let n = POWER_TAXONOMY.len();
        for a in 0u64..(1 << n) {
            for b in 0u64..(1 << n) {
                let sa = powers_to_scope_urns(Powers(a));
                let sb = powers_to_scope_urns(Powers(b));
                assert_eq!(
                    Powers(a).subset_of(Powers(b)),
                    scope_urns_subset(&sa, &sb),
                    "mismatch for a={a:#08b} b={b:#08b}"
                );
            }
        }
    }
}
