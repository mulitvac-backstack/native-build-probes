# Continuous Headspace development builds — 2026-10-18

## Value and feasible scope

The owner requires coherent implementation slices committed/pushed and full package builds attempted continuously, rather than deferring them to final release work. Six native hosted Rust/C compiler environments are verified in run39148769789. Headspace's public source currently contains a nonportable private Bloom path dependency, so actual clean-source builds are expected to fail until that dependency is resolved. Expose this in real product checks now; compiler fixtures are not substitute product/package evidence.

## Finalized first CI contract

The public worker repository remains a build adapter; canonical product source/releases stay on Gitea. Add a manual workflow with one required immutable40-hex source revision and six fixed standard native runner labels. The canonical source URL is fixed to public backstack.io/headspace; no arbitrary repository/commands/credentials. Checkout the worker at its pinned action, fetch the supplied source revision from Gitea with normal Git user agent and verify exact HEAD. Use read-only repository permission, bounded jobs, maximum3concurrent, no private sources/secrets, cache or artifact uploads, no paid runners.

For each target, report intended installer/package-manager formats: Linux `.deb`/`.rpm`, macOS `.app`/`.dmg`/applicable `.pkg` and Homebrew recipe, Windows MSI/WinGet. Attempt the real product pipeline. First validate Cargo path dependencies are present and contained in the public checkout; an absolute/outside/missing private dependency yields an explicit failed/blocked product-build check, never an omitted target or successful package claim. Once portable, invoke native Cargo tests/build and a source-owned package recipe; absent recipes fail explicitly. Preserve phase, revision, target and actionable blocker in a bounded JSON/job summary. No generated installer is claimed while blocked. Artifact retention/delivery, dependency provisioning and full native UI/install/upgrade/signing qualification still need independent evidence.

Dispatch this matrix after each pushed Headspace implementation increment and record its run/statuses beside the product. This first adapter is deliberately scoped to public Headspace; private products need a separately authorized private execution and cost lane. Development package attempts and final release qualification remain distinct.
