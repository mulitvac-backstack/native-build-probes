# Bloom-owned native SDK dependency

Bloom owns SDK versioning, source, recipe, six-target qualification and canonical releases in the private `backstack.io/bloomdb` repository. `native-build-probes` supplies standard hosted native compute only. Headspace consumes a completed, locked Bloom SDK; it does not build or release Bloom.

The new producer targets SDK `0.1.0-alpha.2` from Bloom's `sdk/embedded` profile. The compatibility profile remains `headspace-embedded-sdk-v1`, describing the tested API subset; the Rust binding package remains independently versioned at `0.1.0`. This does not qualify every Bloom engine API or product. The historical alpha1 SDK and its artifact bytes remain unchanged; the Headspace-hosted alpha1 experiment is not an upstream fallback for this pipeline.

## Source and compute contract

The manual `bloom-sdk.yml` workflow takes an exact private Bloom source/recipe revision and SDK SemVer. It uses the same six fixed standard native runner labels, maximum three concurrently. No private repository credential or application checkout is required.

The metadata-only worker pin `profiles/bloom-sdk-input.json` has schema 2: `sdk_version`, `binding_package_version`, `capability_profile`, `archive_sha256`, `profile_sha256`, `inventory_sha256`, and `source{repository,revision,subdirectory}`. Source is fixed to `https://git.multivac.network/backstack.io/bloomdb` at an exact commit and `sdk/embedded`. The pin must agree with workflow inputs and the configured archive digest before extraction. Final pin values are staged only after the Bloom source commit and owner-side archive are frozen.

The owner stages that Bloom-owned private payload through encrypted repository secrets `BLOOM_SDK_01..24`, each at most 12KiB, with `BLOOM_SDK_CHUNKS` and `BLOOM_SDK_SHA256`. Each step exposes only one chunk as `BLOOM_INPUT_CHUNK`. The file-only tar.gz prefix is `bloomdb-sdk/`, containing the owned SDK profile, complete source inventory, `input/bloomdb`, fixed recipe files and three notices. The inventory hashes every payload file except itself. Archive/profile/inventory digests, member hashes/sizes, strict paths and required files are verified before anything is written. Links, duplicate paths, traversal, extra recipe files, oversized input and incomplete inventories fail closed.

The worker executes only the supplied Bloom `recipe/build_bloom.py`. It does not fetch Headspace, import its packaging script or copy its notices. Native compilation, required semantic CTests and a worker-owned ELF/Mach-O/PE check of `bloom-sdk-smoke` must pass. Producer metadata records the Bloom recipe repository/revision/profile path separately from the shared compute repository, workflow, run and worker commit.

## Encrypted deliverables and release authority

Each target produces `bloom-sdk-VERSION-TARGET.aesgcm`, its `.manifest.json`, and `bloom-build-TARGET.json`. Envelope schema 1 uses AES256-GCM from pinned `cryptography==46.0.3`; the 96-bit nonce prefixes ciphertext/tag and exact canonical manifest bytes are authenticated additional data. The key is owner-managed, never printed or passed to compiler children.

Only the static native library, API header, required Rust binding, capabilities and notices enter the encrypted SDK archive. macOS additionally carries the exact tested static Crypto archive; Linux uses system OpenSSL3 and Windows uses BCrypt. Engine C, build trees, user data and raw logs never enter SDK deliverables. Source remains private.

The canonical release is Bloom's private `sdk-vVERSION` at the exact source/recipe commit. The owner-operated Bloom publisher validates all six outputs and publishes only encrypted compiled SDK objects and bounded metadata to the public generic package distribution:

```
https://git.multivac.network/api/packages/backstack.io/generic/bloomdb-sdk/VERSION/FILENAME
```

This distribution is transport, not source or version authority. Its guest-readable objects require no CI repository token. Package upload credentials remain with the owner-side publisher. Published versions and bytes are immutable. GitHub artifact retention is an execution receipt, not the durable authority.

## Consumer lock

The schema 2 lock records `release{repository:'backstack.io/bloomdb',tag:'sdk-vVERSION',revision,distribution:{kind:'gitea_generic',owner:'backstack.io',package:'bloomdb-sdk',version}}`, the compute/recipe producer identity, SDK/source input identity and all six targets. Every target requires ciphertext, manifest and build-receipt SHA256 values. The native receipt must show the exact producer, source, target, artifact name and passed build/tests.

The consumer downloads exactly those three fixed objects for its target, anonymously, from the approved generic endpoint. Redirects, alternate repositories/packages, credentials in URLs, legacy Headspace origins and incomplete locks are rejected. It checks all hashes, release/recipe/source agreement, authenticated manifest, native ABI/tests and archive inventory before relocation. `tested_sdk` echoes the locked release and receipt hash. There is no engine-source fallback or recompilation.

Only six passing native producer outputs can establish the new SDK release and dependency lock. Offline fixtures test the standalone producer subprocess, input/recipe tampering, environment scrubbing, archive/path attacks, architecture checks, authenticated envelopes, complete ownership locks, receipt mismatch and fixed anonymous transport. These fixtures are not hosted native qualification. Application tests, native installer/GUI checks, signing and clean-machine support remain independent gates.

Failure diagnostics may leave only as bounded AES-GCM ciphertext plus authenticated metadata. At most 16MiB of raw private output is retained, with truthful total size/truncation and immutable build identity. Public diagnostics contain only approved source coordinates and compiler codes. Missing encryption never enables plaintext output. The legacy diagnostic envelope field `app_source_revision` carries the Bloom recipe revision for SDK-only jobs; it creates no application dependency.
