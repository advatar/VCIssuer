/-!
  EUDI Formal Issuer: minimal semantic seed.

  This file is intentionally small. It demonstrates the shape of the canonical
  decision model and its first safety theorem. A production development must
  replace Boolean evidence flags with structured evidence and prove the full
  requirements listed in FORMAL_SPEC.md.
-/

namespace EudiIssuer

abbrev Instant := Nat
abbrev SessionId := Nat
abbrev ProfileId := Nat
abbrev SubjectId := Nat
abbrev KeyThumbprint := Nat
abbrev NonceId := Nat
abbrev RequestId := Nat
abbrev DatasetId := Nat

inductive IssuerRole where
  | pid
  | qeaa
  | publicBodyEaa
  | nonQualifiedEaa
  deriving DecidableEq, Repr

inductive CredentialFormat where
  | sdJwtVc
  | mdoc
  deriving DecidableEq, Repr

structure CredentialProfile where
  id : ProfileId
  role : IssuerRole
  format : CredentialFormat
  enabled : Bool
  deviceBindingRequired : Bool
  deriving DecidableEq, Repr

structure Evidence where
  validFrom : Instant
  validUntil : Instant
  freshUntil : Instant
  accepted : Bool
  deriving DecidableEq, Repr

/-- Evidence is usable only inside all three time bounds and when accepted. -/
def Evidence.usableAt (e : Evidence) (now : Instant) : Prop :=
  e.accepted = true ∧
  e.validFrom ≤ now ∧
  now < e.validUntil ∧
  now ≤ e.freshUntil

structure Authorization where
  evidence : Evidence
  profile : ProfileId
  subject : SubjectId
  dataset : DatasetId
  deriving DecidableEq, Repr

structure TokenBinding where
  evidence : Evidence
  dpopKey : KeyThumbprint
  deriving DecidableEq, Repr

structure CredentialProof where
  evidence : Evidence
  nonce : NonceId
  holderKey : KeyThumbprint
  possessionValid : Bool
  deriving DecidableEq, Repr

structure WalletEvidence where
  wia : Evidence
  ka : Option Evidence
  walletNotRevoked : Bool
  holderKeyApproved : Bool
  deriving DecidableEq, Repr

structure SubjectEvidence where
  evidence : Evidence
  subject : SubjectId
  loaHigh : Bool
  entitled : Bool
  claimsCurrent : Bool
  dataset : DatasetId
  deriving DecidableEq, Repr

structure Request where
  id : RequestId
  profile : ProfileId
  subject : SubjectId
  dataset : DatasetId
  dpopKey : KeyThumbprint
  proof : CredentialProof
  expiry : Instant
  deriving DecidableEq, Repr

structure Session where
  id : SessionId
  profile : CredentialProfile
  authorization : Authorization
  token : TokenBinding
  wallet : WalletEvidence
  subject : SubjectEvidence
  expectedNonce : NonceId
  nonceUnused : Bool
  issuerEntitled : Bool
  statusReserved : Bool
  alreadyIssued : Bool
  wiaKaMaintenanceEnd : Instant
  deriving DecidableEq, Repr

/-- Role-dependent subject proofing requirement. -/
def roleEvidenceOk (role : IssuerRole) (subject : SubjectEvidence) : Prop :=
  match role with
  | .pid => subject.loaHigh = true
  | _ => True

/-- Device-binding requirement selected by a validated profile. -/
def deviceBindingOk (profile : CredentialProfile) (wallet : WalletEvidence)
    (proof : CredentialProof) : Prop :=
  if profile.deviceBindingRequired = true then
    wallet.holderKeyApproved = true ∧
    proof.possessionValid = true ∧
    wallet.ka.isSome = true
  else
    proof.possessionValid = true

/--
  Minimal executable authorization predicate. The production predicate must
  include every conjunct in FORMAL_SPEC.md and use structured proof evidence.
-/
def mayIssue (s : Session) (r : Request) (now : Instant) : Prop :=
  s.profile.enabled = true ∧
  s.profile.id = r.profile ∧
  s.issuerEntitled = true ∧
  s.authorization.evidence.usableAt now ∧
  s.authorization.profile = r.profile ∧
  s.authorization.subject = r.subject ∧
  s.authorization.dataset = r.dataset ∧
  s.token.evidence.usableAt now ∧
  s.token.dpopKey = r.dpopKey ∧
  r.proof.evidence.usableAt now ∧
  r.proof.nonce = s.expectedNonce ∧
  s.nonceUnused = true ∧
  r.proof.holderKey = r.dpopKey ∧
  s.wallet.wia.usableAt now ∧
  s.wallet.walletNotRevoked = true ∧
  deviceBindingOk s.profile s.wallet r.proof ∧
  s.subject.evidence.usableAt now ∧
  s.subject.subject = r.subject ∧
  s.subject.dataset = r.dataset ∧
  s.subject.entitled = true ∧
  s.subject.claimsCurrent = true ∧
  roleEvidenceOk s.profile.role s.subject ∧
  r.expiry ≤ s.wiaKaMaintenanceEnd ∧
  s.statusReserved = true ∧
  s.alreadyIssued = false

inductive Error where
  | notAuthorized
  deriving DecidableEq, Repr

structure SignCommand where
  session : SessionId
  request : RequestId
  profile : ProfileId
  subject : SubjectId
  holderKey : KeyThumbprint
  deriving DecidableEq, Repr

/-- The unique pure gateway to a credential signing command. -/
def authorizeSign (s : Session) (r : Request) (now : Instant) :
    Except Error SignCommand :=
  if _h : mayIssue s r now then
    .ok {
      session := s.id
      request := r.id
      profile := r.profile
      subject := r.subject
      holderKey := r.proof.holderKey
    }
  else
    .error .notAuthorized

/-- FI-SAF-001 seed: a successful signing decision implies `mayIssue`. -/
theorem authorizeSign_sound
    (s : Session) (r : Request) (now : Instant) (cmd : SignCommand)
    (h : authorizeSign s r now = .ok cmd) :
    mayIssue s r now := by
  unfold authorizeSign at h
  split at h
  next hMay => exact hMay
  next _hNot => cases h

/-- No disabled profile can produce a signing command. -/
theorem disabled_profile_cannot_sign
    (s : Session) (r : Request) (now : Instant)
    (hDisabled : s.profile.enabled = false) :
    authorizeSign s r now = .error .notAuthorized := by
  simp [authorizeSign, mayIssue, hDisabled]

end EudiIssuer
