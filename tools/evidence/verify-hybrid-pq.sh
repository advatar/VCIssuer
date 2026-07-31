#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
tamarin_output=$(mktemp)
trap 'rm -f "$tamarin_output"' EXIT HUP INT TERM

if grep -nE '(^|[^[:alnum:]_])(sorry|axiom)([^[:alnum:]_]|$)' \
  "$repo_root/formal/lean/EudiIssuer/Model.lean"; then
  echo "Lean source contains a forbidden sorry/axiom placeholder" >&2
  exit 1
fi

(cd "$repo_root/formal/lean" && lake build)
(cd "$repo_root/formal/tamarin" && tamarin-prover eudi_issuance.spthy --prove) \
  >"$tamarin_output"

for lemma in \
  hybrid_issuance_is_atomic \
  hybrid_components_sign_same_tbs \
  classical_component_removal_is_rejected \
  hybrid_generation_agreement
do
  grep -Eq "^[[:space:]]*$lemma \(all-traces\): verified" "$tamarin_output"
done

if grep -Eq '\(all-traces\): falsified|analysis incomplete' "$tamarin_output"; then
  echo "Tamarin reported falsified or incomplete analysis" >&2
  exit 1
fi

(cd "$repo_root/rust" && cargo test --locked -p issuer-service hybrid_codec::tests)

(cd "$repo_root" && shasum -a 256 --check <<'CHECKSUMS'
9470c29cb5745a726fe938b2837707f7500a2755a15c191f715460ba5cccc09f  rust/issuer-service/tests/vectors/hybrid-pq-v1-export-tbs.hex
9522edfe321def42c355e3357a7eabf4d8205df8e75dba619d1e6a0636db972e  rust/issuer-service/tests/vectors/hybrid-pq-v1-recovery-tbs.hex
816f9f5f3e8e62f48ce90a6a8762b0be3013c42a4b029ddaaad4a8ebef83ae03  rust/issuer-service/tests/vectors/hybrid-pq-v2-invalid-profile-tbs.hex
CHECKSUMS
)

echo "Hybrid-PQ evidence gate: PASS"
