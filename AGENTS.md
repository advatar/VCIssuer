```md
# AGENTS

## Working Rules

- Always `git add` and commit and push after creating or editing files. Use clear, descriptive commit messages.
- Verify builds locally before claiming completion for any change.
- After assessing a request, add or update related tasks in `STATUS.md` before implementation. Also, create a github issue with all the details and the plan.
- THIS IS IMPORTANT: Keep going without pausing for confirmation if you already know what the next step is; only ask when a decision is blocking progress.
- Never stage, commit, or alter files you did not edit for the task; leave unrelated changes for their owner.
- Merge a feature into `main` promptly once it is working and verified; do not let completed work drift on long-lived branches.
- Use exactly one active implementation branch per GitHub issue. Reuse that branch for follow-up
  fixes; do not create tangential, duplicate, or differently named branches for the same scope.
- Keep branch names and commits aligned with the issue scope. If the work changes materially,
  update the issue and rename or replace the branch before adding unrelated changes.
- Before declaring an issue complete, verify the intended commits or patch-equivalent changes are
  reachable from `origin/main`; a closed issue, green branch, cherry-pick, or squash is not by
  itself proof that the work is integrated.
- After a verified merge, delete the source branch immediately. Before starting new feature work,
  run `git branch -r --no-merged origin/main` and reconcile any unexpected branch instead of
  accumulating more parallel work.
- Do not merge an ahead branch merely because Git reports commits missing from `main`. Compare its
  effective diff and current normative requirements, run the relevant tests, and explicitly
  retire branches whose work is superseded, duplicated, stale, or unsafe.
- Other agents may be working in the same repo; mind your own business and avoid unrelated investigation or edits.
- When you have unchecked tasks, complete them one by one after passing tests, do not stop
- When adding new functionality add unit tests
- Whenever Rust/UniFFI APIs change, regenerate `ios/Generated/wallet_core.swift`,
  `ios/Generated/wallet_coreFFI.h`, and the local `ios/WalletCore.xcframework`
  with `ios/build-rust-xcframework.sh` before building Xcode; run
  `ios/verify-rust-xcframework.sh` and commit the tracked generated bindings.
```
