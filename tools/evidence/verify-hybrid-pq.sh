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
a6e8ed759186eb3f2e7660e8e7681e90be4d63018d6ecf512ce85944b6582067  rust/issuer-service/tests/vectors/hybrid-pq-v1-component-mutations.json
9ed69d0ae316c0eb221ec87f864d6bd54a7adf5edc639d716f3ac339a93a4f19  rust/issuer-service/tests/vectors/hybrid-pq-v1-component-tbs.hex
9d47d28d9300d2b68652ec9593c31243f04d065d9b4f781f9e47b155bdeb8db5  rust/issuer-service/tests/vectors/hybrid-pq-v1-public-key-envelope.hex
cec567a3d1cfd9152342bda49af2f9327cbfce9ba942d1901e551faf0c2bccc6  rust/issuer-service/tests/vectors/hybrid-pq-v1-signature-envelope.hex
ab61da190318f05e7d659e1477c0694e3499d141a5c748f6b0b19fef908195cb  rust/issuer-service/tests/vectors/hybrid-pq-v1-wrapper-envelope.hex
46926357600682028a5be30d3486eba3201a01ec8b65ba43d80287d5c710363f  rust/issuer-service/tests/vectors/hybrid-pq-v1-wrapper-mutations.json
CHECKSUMS
)

echo "Hybrid-PQ evidence gate: PASS"
