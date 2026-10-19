# Headspace packaging-only native lane

## Value and delivery boundary — passed

The owner requires native packages for all six OS/architecture combinations while
reusing completed application builds. Recompiling an executable to retry its
installer wastes time and invalidates the original byte identity. This lane
downloads the exact six artifacts from one successful manual
`headspace-release.yml` run and executes only SHA-pinned Headspace-owned package
recipes. Headspace's public Gitea repository owns source, recipes and canonical
releases. This worker supplies standard hosted compute; it neither publishes
releases nor receives a Gitea write credential, private SDK or private source.

## Feasibility and finalized design

Reuse the established six native standard labels and native-identity probe.
GitHub's [read-only Actions API](https://docs.github.com/en/rest/actions/artifacts)
supplies completed run/workflow/event/head-SHA and
artifact identity. The run must be `workflow_dispatch` from this fixed public
worker repository and `headspace-release.yml`; all six exact
`headspace-RUNNER-SOURCE` artifact names must exist, be live, and have matching
source/version/build/audit/native receipts. The packaging dispatch supplies the
immutable source SHA, recipe SHA, SemVer and original run ID. GitHub's run API
does not expose original dispatch inputs: source/version are independently
checked in retained app-build artifacts, never guessed from the worker SHA.
The source workflow must expose the explicit `Headspace VERSION @ SOURCE` run
name; that independent dispatch metadata is checked as well. An unrelated
display name is rejected. The existing source workflow added this contract in
worker commit `d568edb` before the next application run.

Only read-only `GH_TOKEN` is used for the fixed GitHub API. Artifact redirects
receive no token; only HTTPS GitHub Actions blob hosts are accepted. Downloads,
ZIP expansion, entry names/types, duplicate names, receipts, executable format,
actual native architecture, all hashes and subprocess time/output are bounded.
No archive member is extracted before the closed five-file input set passes.
No arbitrary repository, URL, recipe path, runner or shell command is accepted.

After input verification the token is removed from child environments. Fetch
only the fixed public Headspace Gitea source at an exact recipe SHA; fetch the
exact app source commit into that same disposable public checkout so recipes can
read versioned assets with `git show`. No credential helper, inherited Git
configuration/askpass, SDK secret, provider token or signing material reaches
the owner recipe. Each source-owned recipe consumes the existing executable;
there is no Cargo, compiler, Bloom build or cache stage.

Linux installs standard native `dpkg-deb`, RPM/rpmbuild, cpio and desktop-file
validation tools. Mac native bundle/DMG tools are built in. Windows installs the
source recipe's pinned WiX 5.0.2 into a temporary tool directory. The workflow
uses read-only repository/Actions permissions, pinned checkout/upload actions,
six fixed standard native jobs, bounded deadlines and three-day artifacts.
Missing prerequisites or a failed source-owned recipe fail that target visibly.

## Owner recipe interface and output contract

Linux and Mac receive `--artifacts INPUT --output EMPTY --target TARGET
--source-revision SOURCE --recipe-revision RECIPE --version VERSION`.
Windows receives the same arguments except `--version` (its recipe reads the
source Cargo version) plus an explicit ephemeral `--wix PATH`.

Linux retains `.deb`/`.rpm` plus their source-owned inventory, Mac `.dmg` plus
inventory, Windows `.msi`/`.winget.yaml` plus inventory. A bounded worker receipt
records original run ID/worker SHA, product source/version, recipe revision/hash,
native identity, input executable SHA and every forwarded file SHA. The recipe
inventory must bind these identities and every native installer it produced.
Only closed-set installers/manifests, JSON inventories and a worker receipt can
leave the packaging lane. Raw input executables, source, logs, secrets and SDKs
are never forwarded. A recipe returning zero alone cannot qualify output bytes.

Structure/payload qualification remains distinct from actual install, GUI,
upgrade, removal and signing. Preserve source-owned native receipts honestly;
do not transform an unrun check into passed. Published alpha.1 bytes and existing
packaging-only Mac repair workflow remain unchanged. This generic lane is for
new source-owned versions and does not mutate any release.

## Testing and execution state

Focused offline tests cover run/artifact provenance, unsafe ZIP members and
bounds, native input receipts, secret stripping, owner recipe commands and
closed-set output identity. They are fixtures, not native package evidence.
The first real run is intentionally not dispatched until the six-target app run
exists; the owner coordinates its run ID and exact recipe revision. Each native
packaging/install target remains pending until its actual job and required
qualification receipts exist.

Implementation checkpoint: 16 focused offline boundary checks pass; the new
workflow YAML parses with all six fixed standard labels. A read-only inspection
of the existing original executable run confirms the API's six-artifact shape,
per-artifact run/head-SHA provenance and SHA256 download digest. The new lane has
not been dispatched; no native package or installer qualification is implied.
