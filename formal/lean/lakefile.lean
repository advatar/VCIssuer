import Lake
open Lake DSL

package «eudi-issuer-model» where

@[default_target]
lean_lib EudiIssuer where
  srcDir := "."
  roots := #[`EudiIssuer.Model]
