# Native build probes

Canonical source: [Gitea](https://git.multivac.network/backstack.io/native-build-probes). The [GitHub worker mirror](https://github.com/mulitvac-backstack/native-build-probes) runs the fixed hosted experiment. All six native compiler jobs passed in [run 39148769789](https://github.com/mulitvac-backstack/native-build-probes/actions/runs/39148769789) on 2026-10-18, source `b1646a8fe49439c84dd9b42b327649a754ceea69`. The [saved reports](verification/2026-10-18-passing-run.json) retain each target and result.

A small public feasibility experiment for native Linux, Windows and macOS compilers on x86_64 and aarch64. It contains fixed, temporary Rust/C hello programs and a macOS Metal probe. It contains no application source, signing credentials or private infrastructure configuration.

Run locally with Python 3 and existing native C tools plus rustup:

```sh
python3 -m unittest -v test_probe.py
python3 probe.py --runner ubuntu-24.04-arm --install-rust
```

Choose the matching fixed runner label. `--install-rust` permits rustup to install only **1.98.1**, minimal profile, for that label's native host; it does not change the default toolchain. Missing rustup/C/VS/Xcode tools fail explicitly rather than installing a toolchain bootstrap or OS packages.

The manual **Native compiler feasibility probe** GitHub workflow has six fixed jobs: `ubuntu-24.04`, `ubuntu-24.04-arm`, `windows-2025`, `windows-11-arm`, `macos-15-intel`, `macos-15`. It runs only in a public repository, with read-only contents permission, pinned official checkout, no persisted checkout credentials, no cache/artifact upload, no inputs, a 15-minute job timeout and at most three concurrent jobs. Standard public runner compute is [free under GitHub's documented policy](https://docs.github.com/en/actions/reference/runners/github-hosted-runners); the recorded run demonstrates access for this public worker repository, rather than a guarantee about other accounts or private repositories. Logs/job summaries use provider retention; this workflow creates no release.

Each result is bounded JSON in logs and the job summary. Success requires native machine/process architecture, exact Rust host/release, and correctly targeted Rust/C executables that actually run. Windows uses `IsWow64Process2` and installed native VS developer tools; macOS checks Apple Silicon hardware and Rosetta translation. A translated probe cannot pass. These checks identify the guest-visible native platform; they do not attest physical hardware or detect every possible hypervisor/transparent emulator.

macOS separately compiles Metal source to AIR and metallib, then uses a small Objective-C program to query `MTLCreateSystemDefaultDevice`. A missing Metal device is an explicit runtime limitation, not a shader compiler failure. **No GPU command buffer, rendering, native UI, installer, clipboard, screen capture or application test runs.** Compiler success is not product release qualification.

See [the gated experiment record](docs/product-development-loop.md). Scoped provider/compiler feasibility, implementation and testing passed: all six jobs executed native Rust 1.98.1 and C binaries; both macOS jobs compiled Metal shaders and found a Metal device. All 13 unit tests passed. GPU dispatch and product packaging remain unverified. Checkout is pinned to [official v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1), resolved through the GitHub API on 2026-10-18; Rust's fixed release is available from the [official distribution manifest](https://static.rust-lang.org/dist/channel-rust-1.98.1.toml).

The separate **Headspace development source and packages** workflow checks an exact public Gitea Headspace revision on all six native targets. Its [contract](docs/headspace-development-ci.md) defines real source tests/builds and each native package format; missing dependencies or recipes fail explicitly. Dispatch after each pushed implementation increment:

```sh
gh workflow run headspace-development.yml --repo mulitvac-backstack/native-build-probes --ref main -f source_revision=<40-hex-Headspace-commit>
```

The adapter and compiler probes have 27 combined offline tests. Compiler probes remain distinct from product package evidence; successful recipe execution also does not establish native installation/signing qualification. The first real product run targets Headspace `ad2cb2f852ecc4ae6264cf9c8b32a831707825e2`: [run 39150148819](https://github.com/mulitvac-backstack/native-build-probes/actions/runs/39150148819). After correcting a Windows path-classification bug, [run 39150293870](https://github.com/mulitvac-backstack/native-build-probes/actions/runs/39150293870) passes all27 adapter tests on every native runner, verifies that exact public source SHA and exposes the private absolute Bloom dependency on every target. [Reports](verification/2026-10-18-headspace-blocked-run.json) retain all installer/package-manager formats as `not_run`; the product package matrix remains blocked.
