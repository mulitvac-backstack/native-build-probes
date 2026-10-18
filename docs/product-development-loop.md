# Shared native build probes — 2026-10-18

## Scope and value — passed

The owner needs reusable native build infrastructure for all products on Linux, macOS and Windows, each x86_64 and aarch64, without buying or maintaining Mac/Windows hardware. Gitea remains the canonical product source and release authority. This separately labeled feasibility probe tests provider access and basic native compiler capability; it is not an application build or package release.

Observable outcome: six hosted jobs report the actual OS/CPU/compiler target, compile and run simple Rust/C programs, and expose platform constraints. macOS additionally compiles a small Metal shader and reports whether a native Metal device exists. A compiler-only check cannot establish native UI, clipboard, capture, installer, upgrade or rendering qualification.

## Feasibility — in progress

Current primary sources: [GitHub runner matrix](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions), [OSXCross](https://github.com/tpoechtrager/osxcross), [GPUI Apple shader builder at the selected revision](https://github.com/zed-industries/zed/blob/56934ec0560bce8929025497411de7f5322fb6ca/crates/gpui_apple/build.rs).

Standard hosted public-repository compute is free; private quotas, larger runners and storage are separate. This probe uses only standard public labels, no artifacts/cache, no private sources/credentials, no signing material and no spending authorization. Account eligibility and all six compiler operations require live jobs. Provider GPU availability is unknown and must be reported independently. Headspace's selected GPUI pin has host-gated shader generation, so Linux cross-compilation is conditional and is not the initial release path. OSXCross is a valid supplementary build approach, not proof that the full native product runs on macOS.

## Probe design — finalized for implementation

One manual-only workflow with six fixed labels: ubuntu-24.04, ubuntu-24.04-arm, windows-2025, windows-11-arm, macos-15-intel, macos-15. No arbitrary repository, revision, shell or command inputs. Read-only contents permission, pinned checkout action, job time limit 15 minutes, maximum three concurrent jobs. Every job validates native machine architecture and compiler target; x64 emulation on ARM cannot satisfy the x64 row. Rust toolchain is fixed at 1.98.1. Native C compiler setup is platform-specific. The Python probe compiles/runs temporary fixture sources and emits bounded JSON and job summary, without dumping environment variables. Failure is explicit; Metal device unavailability is reported as a separate runtime capability limitation. Tests cover target normalization and architecture mismatch rejection. This design finalizes the narrow experiment only.

## Implementation and testing — pending

Source and tests are under this directory. Local tests plus actual hosted run URLs/results must be recorded before claiming provider feasibility passed. No product code, SDK or private infrastructure inventory belongs in this public experiment.

## Packaging — pending, outside this experiment

All six product target combinations and their install/launch/upgrade/removal checks remain required. Product packages/release publication are separate gated work. This repository itself supplies source scripts/workflows, not native application packages. Private-product runner isolation, budgets, artifact retention, signing credentials and canonical Gitea integration remain separate decisions/evidence.
