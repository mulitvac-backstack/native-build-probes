# Shared native build probes — 2026-10-18

## Scope and value — passed

The owner needs reusable native build infrastructure for all products on Linux, macOS and Windows, each x86_64 and aarch64, without buying or maintaining Mac/Windows hardware. Gitea remains the canonical product source and release authority. This separately labeled feasibility probe tests provider access and basic native compiler capability; it is not an application build or package release.

Observable outcome: six hosted jobs report the actual OS/CPU/compiler target, compile and run simple Rust/C programs, and expose platform constraints. macOS additionally compiles a small Metal shader and reports whether a native Metal device exists. A compiler-only check cannot establish native UI, clipboard, capture, installer, upgrade or rendering qualification.

## Provider/compiler feasibility — passed (scoped experiment)

Current primary sources: [GitHub runner matrix](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions), [OSXCross](https://github.com/tpoechtrager/osxcross), [GPUI Apple shader builder at the selected revision](https://github.com/zed-industries/zed/blob/56934ec0560bce8929025497411de7f5322fb6ca/crates/gpui_apple/build.rs).

Standard hosted public-repository compute is free; private quotas, larger runners and storage are separate. This probe uses only standard public labels, no artifacts/cache, no private sources/credentials, no signing material and no spending authorization. The public worker repository successfully ran all six compiler operations in [run 39148769789](https://github.com/mulitvac-backstack/native-build-probes/actions/runs/39148769789), source `b1646a8fe49439c84dd9b42b327649a754ceea69`. Both macOS rows compiled Metal shaders and discovered a native Metal device. No GPU commands were dispatched, so device discovery does not qualify GPU execution or rendering. This evidence establishes access and basic native compiler capability for the recorded standard hosted targets; it does not establish a complete shared service for private products. Cross-compilation remains supplementary and cannot replace native application runtime evidence.

## Probe design — passed

One manual-only workflow with six fixed labels: ubuntu-24.04, ubuntu-24.04-arm, windows-2025, windows-11-arm, macos-15-intel, macos-15. No arbitrary repository, revision, shell or command inputs. Read-only contents permission, pinned checkout action, job time limit 15 minutes, maximum three concurrent jobs. Every job validates native machine architecture and compiler target; x64 emulation on ARM cannot satisfy the x64 row. Rust toolchain is fixed at 1.98.1. Native C compiler setup is platform-specific. The Python probe compiles/runs temporary fixture sources and emits bounded JSON and job summary, without dumping environment variables. Failure is explicit; Metal device unavailability is reported as a separate runtime capability limitation. Tests cover target normalization and architecture mismatch rejection. This design finalizes the narrow experiment only.

## Implementation — passed (compiler probe only)

The stdlib Python probe and fixed six-job workflow implement the finalized experiment. Sources are canonical in [Gitea](https://git.multivac.network/backstack.io/native-build-probes); the [public GitHub worker mirror](https://github.com/mulitvac-backstack/native-build-probes) executes the manual workflow. No product code, SDK or private infrastructure inventory belongs in this public experiment.

## Testing — passed (compiler probe only)

[Passing run 39148769789](https://github.com/mulitvac-backstack/native-build-probes/actions/runs/39148769789), source `b1646a8fe49439c84dd9b42b327649a754ceea69`, passed all six native rows. Exact bounded results are retained in [passing-run.json](../verification/2026-10-18-passing-run.json).

| Hosted label | Native Rust 1.98.1 + C compile/run | Metal shader / device |
| --- | --- | --- |
| ubuntu-24.04 | x86_64 passed | Not applicable |
| ubuntu-24.04-arm | aarch64 passed | Not applicable |
| windows-2025 | x86_64 passed | Not applicable |
| windows-11-arm | aarch64 passed | Not applicable |
| macos-15-intel | x86_64 passed | Compiled / available |
| macos-15 | aarch64 passed | Compiled / available |

Every row validated guest-visible native machine/process architecture and the exact Rust host target. Each hosted job also passed `python -m unittest -v test_probe.py` (13 tests). Local native ARM64 Rust/C compile-run passed. No GPU command buffer, application build, UI, clipboard, capture, signing, installer or upgrade was tested.

First hosted [run 39148518623](https://github.com/mulitvac-backstack/native-build-probes/actions/runs/39148518623), source `4445d1925d3e8fe76ff98b971e36d2e8b5d0aa0c`: both Linux architectures and ARM64 macOS passed native Rust/C compile-run; ARM64 macOS also compiled Metal and reported a device available (no GPU execution/rendering claim). Intel macOS failed an optional hardware sysctl missing on Intel. Both Windows rows validated native CPU/Python/Rust hosts but failed batch-file quoting during C environment setup. Exact fixture reports are preserved in [first-run.json](../verification/2026-10-18-first-run.json).

Probe repairs: Intel absence is accepted only with positive GenuineIntel vendor/native x64/non-Rosetta evidence, other query failures remain failures. Windows passes a controlled raw command line directly to CreateProcess, avoiding list2cmdline's backslash escaping of the batch path. Thirteen unit tests pass including these failure cases, secret-free summaries and allowlisted compiler environment handling. Local native ARM64 Rust/C probe passes. The passing rerun above verifies both repaired Windows rows and Intel macOS; the first-run record remains retained as failure evidence.

## Packaging — pending, outside this experiment

All six product target combinations and their install/launch/upgrade/removal checks remain required. Product packages/release publication are separate gated work. This repository itself supplies source scripts/workflows, not native application packages. Private-product runner isolation, budgets, artifact retention, signing credentials and canonical Gitea integration remain separate decisions/evidence.

## Continuous Headspace product-build adapter

The owner requires source pushes and every package target checked during implementation. The finalized [adapter contract](headspace-development-ci.md) uses one immutable public Gitea Headspace revision, the same six native runner labels, read-only checkout and bounded subprocesses. It validates portable Cargo dependencies before running actual native workspace tests/release build and each source-owned package recipe. Missing dependencies/recipes fail visibly. No compiler fixture replaces a product build and no completed recipe establishes installation/signing qualification.

Worker source `11e26a25dc70bdd990de2198b5edd7d5ba167edc` was committed/pushed to canonical Gitea and the hosted worker mirror. [First product run39150148819](https://github.com/mulitvac-backstack/native-build-probes/actions/runs/39150148819) targets Headspace `ad2cb2f852ecc4ae6264cf9c8b32a831707825e2`. Linux/macOS expose the absolute private Bloom path; both Windows rows exposed a host-dependent path-classification bug in adapter tests. [First-run reports](../verification/2026-10-18-headspace-first-run.json) preserve both outcomes.

The repair `1756cd0f80a0a471919afa774fe1ea9b634c4c21` recognizes POSIX and Windows rooted paths independently of host grammar; all27 offline tests pass. [Rerun39150293870](https://github.com/mulitvac-backstack/native-build-probes/actions/runs/39150293870) checks the same exact Headspace source and retains [six explicit blocked source/package reports](../verification/2026-10-18-headspace-blocked-run.json). Linux `.deb`/`.rpm`, macOS `.app`/`.dmg`/`.pkg`/Homebrew and Windows MSI/WinGet remain `not_run` while the private/nonportable Bloom dependency blocks clean source. Required targets are visible failures rather than omitted or successfully skipped. Next steps are authorized dependency portability, actual source-owned package recipes, artifact receipts/retention and native product qualification; compiler feasibility is already passed separately.

The actual GPUI application increment `e7c3a5f0a936bd8e7b94695a5f4160f0bbf749ba` was pushed and dispatched during implementation in [run39151925893](https://github.com/mulitvac-backstack/native-build-probes/actions/runs/39151925893). All six native clean-source checks fetch/verify that exact revision and expose the existing private Bloom path; every package format remains unrun. [Reports](../verification/2026-10-18-headspace-e7c3a5f-run.json) preserve this separately from local GPUI build/runtime evidence. The preceding feasibility increment's [run39150598356](https://github.com/mulitvac-backstack/native-build-probes/actions/runs/39150598356) likewise records all six dependency blocks [without omission](../verification/2026-10-18-headspace-dfd07d4-run.json).

## Owner-authorized trusted Headspace package lane

Value: the owner now requests every native build and Gitea release downloads.
Feasibility reuses the six verified standard native runners and source-owned
package tools. The private engine's macOS/Windows portability remains pending
actual product builds; those target gates cannot pass by inference.

Design final: preserve both original workflows. A separate trusted manual
`headspace-release.yml` accepts only the immutable public Headspace SHA; it
assembles a source-pinned private SDK from24 bounded encrypted input chunks.
The engine stays ephemeral and is never committed/cached/uploaded. Only validated
compiled packages and bounded hash/qualification receipts leave the runner.
No paid runner or Gitea write secret is introduced. Headspace's
`docs/release/trusted-build-inputs.md` defines the precise lane/privacy contract.

Implementation: the adapter validates SHA/count/paths/decompression bounds,
native identity, SDK environment, product-only tests and required artifact names,
formats and hashes. Real install/runtime qualification remains separate; a
failure is retained honestly alongside valid unsigned development packages.
Thirty-three offline adapter tests pass. The package recipe's five tests and
native ARM64 DEB tool fixture also pass; that fixture is not a product release.
Next: push the coherent adapter, stage the immutable SDK and run the six actual
product builds. Gitea publication is separately owner-authorized and occurs only
after real package checksums and their qualification limits are concrete.

## Bloom-owned SDK alpha.2 cutover — implementation checkpoint

The user explicitly required Bloom builds and releases to belong to Bloom. The
finalized [owner pipeline](bloom-sdk-pipeline.md) now executes only the private
Bloom source-owned profile/recipe, pinned at
`9ed34ee94eb1a2682c2a337dcd86af83bfe3bc87` under `sdk/embedded`. Planned independent
SDK SemVer is `0.1.0-alpha.2`; canonical tag/release is private Bloom
`sdk-v0.1.0-alpha.2`. Public encrypted transport is the Bloom-named Gitea generic
package. Headspace's release adapter consumes the completed six-target SDK lock,
with no engine input or source rebuild. Existing alpha.1 releases and running
application CI remain immutable at their original source and worker revisions.

Value, scoped feasibility and design passed: prior engine native six-target
compile/CTest/install established platform feasibility, while owner-side package
upload/guest download/private-source denial established the new transport.
The new producer validates its complete source/profile/inventory hashes, never
fetches an application recipe and emits source-owned build/test provenance.
Implementation and qualification remain in progress: 61 offline worker tests,
Python syntax and workflow YAML checks passed for this checkpoint, including
malformed gzip/tar constant-error boundaries before any private output is written.
These fixtures do not replace the pending fresh alpha.2 six-target native run.

The fixed worker profile pins archive SHA256
`822a9d3e88acc3209e804c1f81dbac6c1fe4b6dc5d9f1f07dfe547664b331d3e`.
No CI source secrets were changed and no SDK workflow dispatched by this
checkpoint. The owner must stage the exact Bloom-owned archive through
`sdk/embedded/stage_ci_input.py`, then explicitly dispatch `bloom-sdk.yml` with
source revision `9ed34ee94eb1a2682c2a337dcd86af83bfe3bc87` and
`sdk_version=0.1.0-alpha.2`. Six passing native artifacts and owner authentication
are required before canonical Bloom publication and consumer promotion.


## Headspace native transfer feasibility harness (2026-10-19)

Scope: a separate bounded native-API check consumes the exact public Headspace
source SHA, compiling its production AppKit reader/drag destination through the
source-owned independent experiment. Two fixed native Mac architectures; no
Bloom inputs, GPUI app build, host clipboard mutation, cache, paid runner, private
source or credentials. It checks AppKit pasteboard fixtures and synthetic drag
callbacks; physical Safari/Chrome and app integration remain separate pending
acceptance. Only its bounded JSON receipt is retained. Value and existing journey
design are unchanged; this resolves API feasibility before the next app matrix.
