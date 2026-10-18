# Shared native build probes

Read `docs/product-development-loop.md` before changes. This is a labeled capability experiment, not a product build or release. Product source and releases remain on Gitea.

This public probe contains generic fixtures only. Never add private code, source credentials, signing keys, deployment endpoints or infrastructure inventories. Keep fixed standard runner labels and no cache/artifact uploads. Paid runners/resources require separate bounded approval. Workflow inputs must not accept arbitrary shell commands, repositories or revisions. Validate actual native architecture and compiler target; emulation is separate evidence.

Compiler success does not prove GUI, GPU, clipboard, screen capture or installer behavior. Report Metal device absence explicitly. A failed target remains failed; do not silently remove it from the matrix.

## Owner-authorized Headspace package lane

The owner explicitly requested all Headspace builds and publication on its Gitea
release page. The separate manual `headspace-release.yml` lane may consume a
SHA-pinned private Bloom SDK through encrypted repository secret chunks, solely
in ephemeral runner files. This is an exception to the generic probe's no-input
and no-artifact scope, not permission to commit or expose private source or
credentials. No PR triggers, paid runners, source artifacts, raw compiler logs or
build caches. Only validated compiled packages, hash inventories and bounded
public verification receipts may leave that lane. Keep Gitea publication outside
the worker, with no Gitea write credential in Actions. Preserve the original
generic and public-source development lanes. Read Headspace's
`docs/release/trusted-build-inputs.md` and its source-pinned SDK input manifest.

## Bloom-owned SDK producer and consumer boundary

The authorized manual `bloom-sdk.yml` workflow executes only the immutable
private Bloom-owned `sdk/embedded` profile/recipe pinned in
`profiles/bloom-sdk-input.json`. It may receive bounded encrypted source secret
chunks in ephemeral files, but no private repository credential. Only encrypted
compiled SDKs, authenticated bounded receipts and encrypted failure diagnostics
may leave the worker. Canonical SDK source/tag/release belongs to private Bloom;
public Gitea generic package objects are encrypted transport only. Headspace is
a consumer of the complete tested six-target SDK lock and must not rebuild the
engine or fall back to source chunks. Read `docs/bloom-sdk-pipeline.md`. No paid
resources, private source publication, raw logs or Gitea write credentials are
authorized in the worker.
