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

/-- A bounded set of authorized operations as a bitmask (mirrors the Rust `Powers(u64)`), keeping
    the scope-containment relation decidable so the Lean model can mirror it exactly. -/
abbrev Powers := Nat

/-- `a ⊆ grant`: every set bit of `a` is also set in `grant` — monotonic narrowing. Mirrors the
    Rust `Powers::subset_of` (`(self.0 & grant.0) == self.0`). -/
def Powers.subsetOf (a grant : Powers) : Prop := Nat.land a grant = a

inductive IssuerRole where
  | pid
  | qeaa
  | publicBodyEaa
  | nonQualifiedEaa
  /-- Power-of-representation / mandate attestation (ARF Topic 29): a delegator grants a delegate
      (which MAY be an AI agent) a scoped, revocable authority. -/
  | representation
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
  /-- When set, issuance is gated on isolated hybrid-PQ evidence (`Session.hybridPqBound`); mandate
      attestations set this so delegated authority is post-quantum from day one. -/
  requireHybridPq : Bool
  /-- When set, issuance is gated on structured eMRTD chip + liveness evidence
      (`Session.chipEvidence`), downgrade-closed like `requireHybridPq`: the NFC-sourced PID profile
      sets this so a PID can never be minted without a chip read whose Passive Authentication held,
      whose anti-cloning proof held, and whose holder liveness matched the chip portrait. -/
  requireChipLiveness : Bool
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

/-- Delegation context for a power-of-representation issuance (mirrors the Rust `Delegation`). The
    delegator is authenticated by their own presented attestation carried as `delegatorEvidence`;
    `grant` is the authority the delegator actually holds; `delegateKey` is the key the resulting
    mandate is bound to — the AI agent's holder key. -/
structure Delegation where
  delegatorEvidence : Evidence
  delegator : SubjectId
  delegateKey : KeyThumbprint
  grant : Powers
  mandateNotRevoked : Bool
  deriving DecidableEq, Repr

/-- Structured evidence from an in-wallet eMRTD (passport / national eID) chip read, carried when
    issuing an NFC-sourced PID (mirrors the Rust `ChipLivenessEvidence`). Each boolean is a verdict
    the issuer itself reproduced over the raw data groups + EF.SOD the reader delivered:
    `sodPassiveAuth` — Passive Authentication held (EF.SOD signed by a Document Signer chaining to a
    trusted CSCA, every read DG's hash matches); `chipAuthentic` — an anti-cloning proof held
    (Chip/Active Authentication or PACE-CAM); `livenessMatched` — a fresh holder liveness capture
    matched the DG2 portrait. `subject` is the identity the read establishes and must equal the
    request subject. -/
structure ChipLivenessEvidence where
  evidence : Evidence
  subject : SubjectId
  sodPassiveAuth : Bool
  chipAuthentic : Bool
  livenessMatched : Bool
  deriving DecidableEq, Repr

structure Request where
  id : RequestId
  profile : ProfileId
  subject : SubjectId
  dataset : DatasetId
  dpopKey : KeyThumbprint
  proof : CredentialProof
  expiry : Instant
  /-- Powers the mandate would authorize. Ignored unless the profile role is `representation`;
      must be a non-empty subset of the delegator's `grant`. -/
  requestedPowers : Powers
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
  /-- Isolated hybrid-PQ evidence is present and accepted for this session (downgrade-closed). -/
  hybridPqBound : Bool
  /-- Present iff the profile role is `representation`; carries the authenticated delegator, the
      delegate (agent) key, and the delegator's live grant. -/
  delegation : Option Delegation
  /-- Present when the issuer verified an eMRTD chip read + holder liveness for this session (the
      NFC-sourced PID flow). Required — and checked — iff `profile.requireChipLiveness`. -/
  chipEvidence : Option ChipLivenessEvidence
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

/-- Delegation gate for power-of-representation issuance (mirrors the Rust `representation_ok`).
    For a non-`representation` role this is vacuously `True`. For `representation` it requires a
    live authenticated delegator, a mandate bound to the delegate (agent) key that proved
    possession, and a NON-EMPTY set of requested powers that is a SUBSET of the delegator's own
    grant (monotonic narrowing — a delegate can never be granted authority the delegator lacked). -/
def representationOk (s : Session) (r : Request) (now : Instant) : Prop :=
  match s.profile.role with
  | .representation =>
    match s.delegation with
    | some d =>
      d.delegatorEvidence.usableAt now ∧
      d.mandateNotRevoked = true ∧
      d.delegateKey = r.proof.holderKey ∧
      r.requestedPowers ≠ 0 ∧
      Powers.subsetOf r.requestedPowers d.grant
    | none => False
  | _ => True

/-- Chip + liveness gate for an NFC-sourced PID issuance (mirrors the Rust `chip_liveness_ok`).
    Downgrade-closed like the hybrid-PQ gate: the `mayIssue` conjunct only *invokes* this when
    `profile.requireChipLiveness` is set, and then it demands a chip-read evidence value that is
    fresh, Passive-Authenticated against a trusted CSCA, anti-clone proven, liveness-matched, and
    bound to the request subject. A required profile with no `chipEvidence` fails closed. -/
def chipLivenessOk (s : Session) (r : Request) (_now : Instant) : Prop :=
  match s.chipEvidence with
  | some e =>
    e.evidence.usableAt _now ∧
    e.sodPassiveAuth = true ∧
    e.chipAuthentic = true ∧
    e.livenessMatched = true ∧
    e.subject = r.subject
  | none => False

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
  s.alreadyIssued = false ∧
  -- Post-quantum: when the profile requires it (mandates do), isolated hybrid-PQ evidence must be
  -- present — downgrade-closed.
  (s.profile.requireHybridPq = false ∨ s.hybridPqBound = true) ∧
  -- Delegation: monotonic-narrowing power-of-representation gate.
  representationOk s r now ∧
  -- NFC-sourced PID: when the profile requires it, a chip read with verified Passive
  -- Authentication, anti-cloning, and portrait-matched liveness must be present — downgrade-closed.
  (s.profile.requireChipLiveness = false ∨ chipLivenessOk s r now)

noncomputable instance mayIssueDecidable (s : Session) (r : Request) (now : Instant) :
    Decidable (mayIssue s r now) := Classical.propDecidable _

inductive Error where
  | notAuthorized
  deriving DecidableEq, Repr

structure SignCommand where
  session : SessionId
  request : RequestId
  profile : ProfileId
  subject : SubjectId
  holderKey : KeyThumbprint
  /-- For a `representation` mandate: the authenticated delegator the mandate acts on behalf of,
      and the exact powers granted (already narrowed to a subset of the delegator's grant). -/
  onBehalfOf : Option SubjectId
  grantedPowers : Powers
  deriving DecidableEq, Repr

/-- The delegator a `representation` mandate acts on behalf of (mirrors the Rust tuple match). -/
def onBehalfOfFor (s : Session) : Option SubjectId :=
  match s.profile.role, s.delegation with
  | .representation, some d => some d.delegator
  | _, _ => none

/-- The powers a `representation` mandate grants (already narrowed); empty for non-delegation. -/
def grantedPowersFor (s : Session) (r : Request) : Powers :=
  match s.profile.role, s.delegation with
  | .representation, some _ => r.requestedPowers
  | _, _ => 0

/-- The unique pure gateway to a credential signing command. -/
noncomputable def authorizeSign (s : Session) (r : Request) (now : Instant) :
    Except Error SignCommand :=
  if _h : mayIssue s r now then
    .ok {
      session := s.id
      request := r.id
      profile := r.profile
      subject := r.subject
      holderKey := r.proof.holderKey
      onBehalfOf := onBehalfOfFor s
      grantedPowers := grantedPowersFor s r
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

/-- A signing command exposes the replay, holder-binding, and status gates used by the runtime. -/
theorem authorizeSign_security_gates
    (s : Session) (r : Request) (now : Instant) (cmd : SignCommand)
    (h : authorizeSign s r now = .ok cmd) :
    s.profile.enabled = true ∧
    r.proof.nonce = s.expectedNonce ∧
    s.nonceUnused = true ∧
    r.proof.holderKey = r.dpopKey ∧
    s.statusReserved = true ∧
    s.alreadyIssued = false := by
  have hMay := authorizeSign_sound s r now cmd h
  rcases hMay with
    ⟨hEnabled, _, _, _, _, _, _, _, _, _, hProofNonce, hNonceUnused,
      hHolderBinding, _, _, _, _, _, _, _, _, _, _, hStatus, hNotIssued, _, _⟩
  exact ⟨hEnabled, hProofNonce, hNonceUnused, hHolderBinding, hStatus, hNotIssued⟩

/-- A successful PID signing decision always carries LoA-high subject evidence. -/
theorem pid_authorizeSign_requires_loa_high
    (s : Session) (r : Request) (now : Instant) (cmd : SignCommand)
    (hRole : s.profile.role = .pid)
    (h : authorizeSign s r now = .ok cmd) :
    s.subject.loaHigh = true := by
  have hMay := authorizeSign_sound s r now cmd h
  rcases hMay with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, hRoleEvidence, _⟩
  simp [roleEvidenceOk, hRole] at hRoleEvidence
  exact hRoleEvidence

/-- Successful issuance cannot exceed the WIA/KA maintenance period. -/
theorem authorizeSign_respects_wallet_maintenance_bound
    (s : Session) (r : Request) (now : Instant) (cmd : SignCommand)
    (h : authorizeSign s r now = .ok cmd) :
    r.expiry ≤ s.wiaKaMaintenanceEnd := by
  have hMay := authorizeSign_sound s r now cmd h
  rcases hMay with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, hBound, _⟩
  exact hBound

/-! ## Power-of-representation (delegation) safety theorems

These mirror the Rust `issuer-core` delegation gate (`representation_ok` + the two `may_issue`
conjuncts). They establish that a successful power-of-representation signing decision can never
exceed the delegator's own authority, is bound to the delegate (agent) key, and is post-quantum. -/

/-- `mayIssue` entails the delegation gate (the 27th conjunct). -/
theorem mayIssue_representationOk (s : Session) (r : Request) (now : Instant)
    (h : mayIssue s r now) : representationOk s r now := by
  rcases h with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, hRep, _⟩
  exact hRep

/-- `mayIssue` entails the post-quantum gate (the 26th conjunct). -/
theorem mayIssue_hybridPq (s : Session) (r : Request) (now : Instant)
    (h : mayIssue s r now) :
    s.profile.requireHybridPq = false ∨ s.hybridPqBound = true := by
  rcases h with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, hPq, _⟩
  exact hPq

/-- On a successful `.ok`, the command's delegation fields are exactly the selector values. -/
theorem authorizeSign_ok_fields
    (s : Session) (r : Request) (now : Instant) (cmd : SignCommand)
    (h : authorizeSign s r now = .ok cmd) :
    cmd.onBehalfOf = onBehalfOfFor s ∧ cmd.grantedPowers = grantedPowersFor s r := by
  unfold authorizeSign at h
  split at h
  next _ =>
    injection h with hcmd
    subst hcmd
    exact ⟨rfl, rfl⟩
  next _ => cases h

/-- Headline delegation-safety theorem: a successful power-of-representation signing decision can
    never grant a power the delegator did not hold (monotonic narrowing), is bound to the delegate
    (agent) key that proved possession, requires a live un-revoked authenticated delegator and a
    non-empty scope, and acts on behalf of exactly that delegator. -/
theorem representation_authorizeSign_narrows_and_binds
    (s : Session) (r : Request) (now : Instant) (cmd : SignCommand)
    (hRole : s.profile.role = .representation)
    (h : authorizeSign s r now = .ok cmd) :
    ∃ d, s.delegation = some d ∧
      d.delegatorEvidence.usableAt now ∧
      d.mandateNotRevoked = true ∧
      d.delegateKey = r.proof.holderKey ∧
      r.requestedPowers ≠ 0 ∧
      Powers.subsetOf r.requestedPowers d.grant ∧
      cmd.onBehalfOf = some d.delegator ∧
      cmd.grantedPowers = r.requestedPowers := by
  have hMay := authorizeSign_sound s r now cmd h
  have hRep := mayIssue_representationOk s r now hMay
  have hFields := authorizeSign_ok_fields s r now cmd h
  cases hDel : s.delegation with
  | none =>
    simp only [representationOk, hRole, hDel] at hRep
  | some d =>
    simp only [representationOk, hRole, hDel] at hRep
    obtain ⟨hUsable, hRevoked, hKey, hNonEmpty, hSubset⟩ := hRep
    refine ⟨d, rfl, hUsable, hRevoked, hKey, hNonEmpty, hSubset, ?_, ?_⟩
    · rw [hFields.1]; simp [onBehalfOfFor, hRole, hDel]
    · rw [hFields.2]; simp [grantedPowersFor, hRole, hDel]

/-- A `representation` role with no delegation context can never sign. -/
theorem representation_without_delegation_cannot_sign
    (s : Session) (r : Request) (now : Instant)
    (hRole : s.profile.role = .representation)
    (hNoDel : s.delegation = none) :
    authorizeSign s r now = .error .notAuthorized := by
  have hNotMay : ¬ mayIssue s r now := by
    intro hMay
    have hRep := mayIssue_representationOk s r now hMay
    simp only [representationOk, hRole, hNoDel] at hRep
  unfold authorizeSign
  rw [dif_neg hNotMay]

/-- When the profile requires it (mandates do), a successful signing decision proves the isolated
    hybrid post-quantum evidence was present — delegated authority is post-quantum from day one. -/
theorem authorizeSign_requires_hybrid_pq_when_profile_requires
    (s : Session) (r : Request) (now : Instant) (cmd : SignCommand)
    (hReq : s.profile.requireHybridPq = true)
    (h : authorizeSign s r now = .ok cmd) :
    s.hybridPqBound = true := by
  have hMay := authorizeSign_sound s r now cmd h
  rcases mayIssue_hybridPq s r now hMay with hFalse | hTrue
  · rw [hReq] at hFalse; simp at hFalse
  · exact hTrue

/-! ## NFC-sourced PID (eMRTD chip + liveness) safety theorems

These mirror the Rust `issuer-core` chip+liveness gate (`chip_liveness_ok` + the 28th `may_issue`
conjunct). They establish that a successful NFC-sourced PID signing decision can never be produced
without a chip read whose Passive Authentication verified, whose anti-cloning proof held, and whose
holder liveness matched the chip portrait — bound to the request subject. -/

/-- `mayIssue` entails the chip+liveness gate (the 28th conjunct). -/
theorem mayIssue_chipLivenessOk (s : Session) (r : Request) (now : Instant)
    (h : mayIssue s r now) :
    s.profile.requireChipLiveness = false ∨ chipLivenessOk s r now := by
  rcases h with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, hChip⟩
  exact hChip

/-- When the profile requires it (the NFC-sourced PID profile does), a successful signing decision
    proves the chip+liveness evidence was present and verified — downgrade-closed. -/
theorem authorizeSign_requires_chip_liveness_when_profile_requires
    (s : Session) (r : Request) (now : Instant) (cmd : SignCommand)
    (hReq : s.profile.requireChipLiveness = true)
    (h : authorizeSign s r now = .ok cmd) :
    chipLivenessOk s r now := by
  have hMay := authorizeSign_sound s r now cmd h
  rcases mayIssue_chipLivenessOk s r now hMay with hFalse | hTrue
  · rw [hReq] at hFalse; simp at hFalse
  · exact hTrue

/-- Headline NFC-PID-safety theorem: when the profile requires chip+liveness, a successful signing
    decision proves a chip read was present whose Passive Authentication held, whose anti-cloning
    proof held, whose holder liveness matched the DG2 portrait, and whose subject is exactly the
    request subject — so a PID can never be minted from a forged, cloned, or mismatched chip read. -/
theorem chip_liveness_pid_authorizeSign_binds_verified_chip
    (s : Session) (r : Request) (now : Instant) (cmd : SignCommand)
    (hReq : s.profile.requireChipLiveness = true)
    (h : authorizeSign s r now = .ok cmd) :
    ∃ e, s.chipEvidence = some e ∧
      e.evidence.usableAt now ∧
      e.sodPassiveAuth = true ∧
      e.chipAuthentic = true ∧
      e.livenessMatched = true ∧
      e.subject = r.subject := by
  have hChip := authorizeSign_requires_chip_liveness_when_profile_requires s r now cmd hReq h
  cases hCE : s.chipEvidence with
  | none =>
    simp only [chipLivenessOk, hCE] at hChip
  | some e =>
    simp only [chipLivenessOk, hCE] at hChip
    obtain ⟨hUsable, hPa, hAuth, hLive, hSubj⟩ := hChip
    exact ⟨e, rfl, hUsable, hPa, hAuth, hLive, hSubj⟩

/-! ## Experimental hybrid post-quantum issuance boundary

The cryptographic algorithms remain abstract: this model proves the issuer's
closed AND-policy, identical-TBS binding, logical-generation agreement, and
downgrade rejection. It does not prove ES256 or ML-DSA arithmetic.
-/

abbrev HybridTbsId := Nat
abbrev HybridKeyGeneration := Nat

structure HybridVerification where
  profileSupported : Bool
  hybridRequired : Bool
  classicalPresent : Bool
  postQuantumPresent : Bool
  classicalValid : Bool
  postQuantumValid : Bool
  classicalTbs : HybridTbsId
  postQuantumTbs : HybridTbsId
  expectedTbs : HybridTbsId
  classicalGeneration : HybridKeyGeneration
  postQuantumGeneration : HybridKeyGeneration
  expectedGeneration : HybridKeyGeneration
  deriving DecidableEq, Repr

/-- The only experimental hybrid acceptance predicate: every conjunct is mandatory. -/
def hybridAccept (v : HybridVerification) : Prop :=
  v.profileSupported = true ∧
  v.hybridRequired = true ∧
  v.classicalPresent = true ∧
  v.postQuantumPresent = true ∧
  v.classicalValid = true ∧
  v.postQuantumValid = true ∧
  v.classicalTbs = v.expectedTbs ∧
  v.postQuantumTbs = v.expectedTbs ∧
  v.classicalGeneration = v.expectedGeneration ∧
  v.postQuantumGeneration = v.expectedGeneration ∧
  0 < v.expectedGeneration

noncomputable instance hybridAcceptDecidable (v : HybridVerification) :
    Decidable (hybridAccept v) := Classical.propDecidable _

structure HybridSignCommand where
  authorized : SignCommand
  tbs : HybridTbsId
  generation : HybridKeyGeneration
  deriving DecidableEq, Repr

/-- Hybrid signing is reachable only after both ordinary authorization and hybrid AND-policy. -/
noncomputable def authorizeHybridSign
    (s : Session) (r : Request) (now : Instant) (v : HybridVerification) :
    Except Error HybridSignCommand :=
  match authorizeSign s r now with
  | .error error => .error error
  | .ok command =>
      if _h : hybridAccept v then
        .ok { authorized := command, tbs := v.expectedTbs, generation := v.expectedGeneration }
      else
        .error .notAuthorized

/-- A hybrid command proves both the ordinary issuer gate and the hybrid AND-policy. -/
theorem authorizeHybridSign_sound
    (s : Session) (r : Request) (now : Instant) (v : HybridVerification)
    (cmd : HybridSignCommand) (h : authorizeHybridSign s r now v = .ok cmd) :
    mayIssue s r now ∧ hybridAccept v := by
  unfold authorizeHybridSign at h
  cases hSign : authorizeSign s r now with
  | error error => simp [hSign] at h
  | ok command =>
      simp [hSign] at h
      split at h
      next hHybrid =>
        exact ⟨authorizeSign_sound s r now command hSign, hHybrid⟩
      next _ => simp_all

/-- Acceptance requires both signature components to be present and valid. -/
theorem hybrid_accept_requires_both_components (v : HybridVerification)
    (h : hybridAccept v) :
    v.classicalPresent = true ∧ v.postQuantumPresent = true ∧
    v.classicalValid = true ∧ v.postQuantumValid = true := by
  rcases h with ⟨_, _, hCp, hPqp, hCv, hPqv, _⟩
  exact ⟨hCp, hPqp, hCv, hPqv⟩

/-- Both algorithms authorize the exact same expected TBS identifier. -/
theorem hybrid_accept_same_tbs (v : HybridVerification) (h : hybridAccept v) :
    v.classicalTbs = v.postQuantumTbs ∧ v.classicalTbs = v.expectedTbs := by
  rcases h with ⟨_, _, _, _, _, _, hClassical, hPq, _⟩
  exact ⟨hClassical.trans hPq.symm, hClassical⟩

/-- Both component keys belong to one non-zero logical generation. -/
theorem hybrid_accept_generation_agreement (v : HybridVerification) (h : hybridAccept v) :
    v.classicalGeneration = v.postQuantumGeneration ∧
    v.classicalGeneration = v.expectedGeneration ∧ 0 < v.expectedGeneration := by
  rcases h with ⟨_, _, _, _, _, _, _, _, hClassical, hPq, hPositive⟩
  exact ⟨hClassical.trans hPq.symm, hClassical, hPositive⟩

/-- Removing the PQ component is a downgrade and cannot satisfy hybrid acceptance. -/
theorem classical_only_cannot_hybrid_accept (v : HybridVerification)
    (hMissing : v.postQuantumPresent = false) : ¬ hybridAccept v := by
  intro h
  have hPresent := (hybrid_accept_requires_both_components v h).2.1
  simp [hMissing] at hPresent

/-- Removing the classical component cannot turn the profile into PQ-only acceptance. -/
theorem post_quantum_only_cannot_hybrid_accept (v : HybridVerification)
    (hMissing : v.classicalPresent = false) : ¬ hybridAccept v := by
  intro h
  have hPresent := (hybrid_accept_requires_both_components v h).1
  simp [hMissing] at hPresent

/-- Hybrid-required policy cannot be silently negotiated down to classical mode. -/
theorem classical_downgrade_cannot_hybrid_accept (v : HybridVerification)
    (hDowngraded : v.hybridRequired = false) : ¬ hybridAccept v := by
  intro h
  have hRequired := h.2.1
  simp [hDowngraded] at hRequired

/-- An unsupported profile is rejected before component validity can matter. -/
theorem unsupported_profile_cannot_hybrid_accept (v : HybridVerification)
    (hUnsupported : v.profileSupported = false) : ¬ hybridAccept v := by
  intro h
  have hSupported := h.1
  simp [hUnsupported] at hSupported

end EudiIssuer
