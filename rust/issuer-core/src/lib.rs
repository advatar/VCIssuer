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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub id: RequestId,
    pub profile: ProfileId,
    pub subject: SubjectId,
    pub dataset: DatasetId,
    pub dpop_key: KeyThumbprint,
    pub proof: CredentialProof,
    pub expiry: Instant,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignCommand {
    pub session: SessionId,
    pub request: RequestId,
    pub profile: ProfileId,
    pub subject: SubjectId,
    pub holder_key: KeyThumbprint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionError {
    NotAuthorized,
}

#[must_use]
pub const fn role_evidence_ok(role: IssuerRole, subject: SubjectEvidence) -> bool {
    match role {
        IssuerRole::Pid => subject.loa_high,
        IssuerRole::Qeaa | IssuerRole::PublicBodyEaa | IssuerRole::NonQualifiedEaa => true,
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
}

/// The sole pure gateway to a credential signing command.
pub const fn authorize_sign(
    session: Session,
    request: Request,
    now: Instant,
) -> Result<SignCommand, DecisionError> {
    if may_issue(session, request, now) {
        Ok(SignCommand {
            session: session.id,
            request: request.id,
            profile: request.profile,
            subject: request.subject,
            holder_key: request.proof.holder_key,
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
        };
        (session, request)
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
