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
    /// When set, issuance is gated on isolated hybrid-PQ evidence (`Session::hybrid_pq_bound`).
    /// Mandate attestations set this so delegated authority is post-quantum from day one, even
    /// though the EU Business Wallet does not yet require PQ.
    pub require_hybrid_pq: bool,
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
        };
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
}
