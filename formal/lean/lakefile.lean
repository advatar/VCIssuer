import Lake
open Lake DSL

package «eudi-issuer-model» where
  -- Pin a specific Lean toolchain in lean-toolchain before use.

lean_lib EudiIssuer where
  srcDir := "EudiIssuer"
